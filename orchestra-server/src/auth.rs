//! Bearer-token authentication middleware. Supports multi-operator lookup
//! with constant-time comparison, falling back to the legacy admin token.
//! Includes per-IP rate limiting to prevent brute-force token attacks.

use axum::{
    extract::State,
    http::{header, Request, StatusCode},
    middleware::Next,
    response::Response,
};
use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;

use crate::state::AppState;

/// Identity of the authenticated operator, attached as a request extension.
///
/// P1-26: Now carries the operator's permission set for RBAC enforcement.
#[derive(Clone)]
pub struct AuthenticatedUser {
    /// Operator identifier (matches `OperatorRecord.id` or "admin" for the
    /// legacy single-token fallback).
    pub id: String,
    /// Permission flags from the operator's config entry.
    /// Common values: `"read"`, `"write"`, `"admin"`.
    pub permissions: Vec<String>,
}

impl AuthenticatedUser {
    /// Check whether the user holds a specific permission.
    pub fn has_permission(&self, perm: &str) -> bool {
        self.permissions.iter().any(|p| p == perm)
    }

    /// P1-26: Require one of the given permissions.  Returns an error response
    /// (HTTP 403) if the user lacks all of them.
    pub fn require_any_permission(
        &self,
        required: &[&str],
    ) -> Result<(), (axum::http::StatusCode, String)> {
        if required.iter().any(|r| self.has_permission(r)) {
            Ok(())
        } else {
            Err((
                axum::http::StatusCode::FORBIDDEN,
                format!(
                    "insufficient permissions: requires one of [{}]",
                    required.join(", ")
                ),
            ))
        }
    }
}

/// Simple sliding-window rate limiter to prevent brute-force auth attempts.
pub struct RateLimiter {
    attempts: AtomicU64,
    window_start: Mutex<Instant>,
    max_attempts: u64,
    window_duration: Duration,
}

impl RateLimiter {
    pub fn new(max: u64, window: Duration) -> Self {
        Self {
            attempts: AtomicU64::new(0),
            window_start: Mutex::new(Instant::now()),
            max_attempts: max,
            window_duration: window,
        }
    }

    fn check(&self) -> Result<(), StatusCode> {
        let mut start = self.window_start.lock().unwrap();
        if start.elapsed() > self.window_duration {
            *start = Instant::now();
            // Release ordering ensures the window_start reset is visible to
            // other threads before they observe the zeroed counter (pairs with
            // the AcqRel fetch_add below).
            self.attempts.store(0, Ordering::Release);
        }
        // Acquire+Release ordering guarantees we see the latest counter value
        // (including any concurrent reset) and that our increment is visible to
        // subsequent readers.  Prevents stale reads under high concurrency.
        let count = self.attempts.fetch_add(1, Ordering::AcqRel);
        if count >= self.max_attempts {
            Err(StatusCode::TOO_MANY_REQUESTS)
        } else {
            Ok(())
        }
    }
}

/// Per-IP sliding-window rate limiter.  Each client IP gets its own
/// independent `RateLimiter`, preventing one attacker from exhausting
/// the global budget and blocking all other IPs.
pub struct PerIpRateLimiter {
    limiters: DashMap<IpAddr, RateLimiter>,
    max_attempts: u64,
    window_duration: Duration,
}

impl PerIpRateLimiter {
    pub fn new(max: u64, window: Duration) -> Self {
        Self {
            limiters: DashMap::new(),
            max_attempts: max,
            window_duration: window,
        }
    }

    /// Check whether the given IP is allowed to make another auth attempt.
    pub fn check(&self, ip: &IpAddr) -> Result<(), StatusCode> {
        // Lazy-entry: insert a fresh limiter if this IP hasn't been seen.
        let limiter = self
            .limiters
            .entry(*ip)
            .or_insert_with(|| RateLimiter::new(self.max_attempts, self.window_duration));
        limiter.check()
    }

    /// Evict expired entries to prevent unbounded memory growth.
    /// Call periodically (e.g. every few minutes from a background task).
    pub fn purge_expired(&self) {
        self.limiters.retain(|_ip, limiter| {
            let start = limiter.window_start.lock().unwrap();
            start.elapsed() <= limiter.window_duration
        });
    }
}

/// Extract the client IP from `axum::extract::ConnectInfo`, falling back
/// to the `X-Forwarded-For` header (first entry) and finally to
/// `127.0.0.1` if neither is available.
///
/// Returns `(ip, is_trusted)` where `is_trusted` indicates the IP came from
/// the kernel socket address (ConnectInfo).  When `is_trusted` is false the
/// IP is XFF-derived or a fallback and should be rate-limited more
/// aggressively (see [`rate_limit_key`]).
pub fn extract_client_ip(req: &Request<axum::body::Body>) -> (IpAddr, bool) {
    // 1. Try ConnectInfo (AXUM direct-connect socket address).
    if let Some(ci) = req
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
    {
        return (ci.0.ip(), true);
    }
    // 2. Try X-Forwarded-For (reverse-proxy scenario).
    if let Some(xff) = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
    {
        if let Some(first) = xff.split(',').next() {
            if let Ok(ip) = first.trim().parse::<IpAddr>() {
                return (ip, false);
            }
        }
    }
    // 3. Fallback.
    ("127.0.0.1".parse().unwrap(), false)
}

/// Derive the rate-limit key from a (possibly untrusted) client IP.
///
/// When the IP is trusted (ConnectInfo-derived), use it directly — the kernel
/// guarantees it reflects the actual TCP source and cannot be spoofed.
///
/// When the IP is untrusted (XFF-derived or the 127.0.0.1 fallback), widen
/// the key to a subnet to mitigate two attack vectors:
///
/// * **XFF rotation**: an attacker who can set arbitrary `X-Forwarded-For`
///   headers can cycle through fake IPs, each of which would get its own
///   rate-limit bucket.  By bucketing on `/24` (IPv4) or `/64` (IPv6) the
///   attacker's entire subnet shares one bucket.
/// * **Fallback collapse**: when neither ConnectInfo nor XFF is available,
///   all clients collapse to `127.0.0.1`.  A single global "unknown" bucket
///   prevents unrelated clients from each getting a fresh limiter.
fn rate_limit_key(ip: IpAddr, trusted: bool) -> IpAddr {
    if trusted {
        return ip;
    }
    match ip {
        IpAddr::V4(v4) => {
            // Mask to /24 so all IPs in the same /24 share one bucket.
            let octets = v4.octets();
            let masked = std::net::Ipv4Addr::new(octets[0], octets[1], octets[2], 0);
            IpAddr::from(masked)
        }
        IpAddr::V6(v6) => {
            // Mask to /64 so all IPs in the same /64 share one bucket.
            let mut segments = v6.segments();
            segments[4] = 0;
            segments[5] = 0;
            segments[6] = 0;
            segments[7] = 0;
            IpAddr::from(std::net::Ipv6Addr::from(segments))
        }
    }
}

pub async fn require_bearer(
    State(state): State<Arc<AppState>>,
    mut req: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let (client_ip, ip_trusted) = extract_client_ip(&req);
    let rl_key = rate_limit_key(client_ip, ip_trusted);

    // Check rate limit *before* attempting auth so that even the first
    // batch of failures is counted against the budget.  Previously the
    // check was after the failed auth, meaning the first `max_attempts`
    // failures always returned 401 instead of 429.
    state.auth_rate_limiters.check(&rl_key)?;

    let header_val = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let presented = header_val.strip_prefix("Bearer ").unwrap_or("");

    // 1. Try the multi-operator store (constant-time SHA-256 hash comparison).
    if let Some((operator_id, permissions)) = state.authenticate_operator(presented) {
        req.extensions_mut().insert(AuthenticatedUser {
            id: operator_id,
            permissions,
        });
        return Ok(next.run(req).await);
    }

    // 2. Fallback: legacy single admin token — hash the presented value
    //    and compare the SHA-256 digests with constant-time equality.
    let presented_hash = crate::config::OperatorRecord::hash_token(presented);
    let ok: bool = presented_hash
        .as_bytes()
        .ct_eq(state.admin_token_hash.as_bytes())
        .into();
    if ok {
        // P1-26: Legacy admin token gets full admin permissions.
        req.extensions_mut().insert(AuthenticatedUser {
            id: "admin".into(),
            permissions: vec!["read".into(), "write".into(), "admin".into()],
        });
        return Ok(next.run(req).await);
    }

    Err(StatusCode::UNAUTHORIZED)
}
