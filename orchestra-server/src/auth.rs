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
            self.attempts.store(0, Ordering::Relaxed);
        }
        let count = self.attempts.fetch_add(1, Ordering::Relaxed);
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
pub fn extract_client_ip(req: &Request<axum::body::Body>) -> IpAddr {
    // 1. Try ConnectInfo (AXUM direct-connect socket address).
    if let Some(ci) = req
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
    {
        return ci.0.ip();
    }
    // 2. Try X-Forwarded-For (reverse-proxy scenario).
    if let Some(xff) = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
    {
        if let Some(first) = xff.split(',').next() {
            if let Ok(ip) = first.trim().parse::<IpAddr>() {
                return ip;
            }
        }
    }
    // 3. Fallback.
    "127.0.0.1".parse().unwrap()
}

pub async fn require_bearer(
    State(state): State<Arc<AppState>>,
    mut req: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let client_ip = extract_client_ip(&req);

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

    // Only failed bearer attempts consume the auth limiter. Authenticated
    // dashboard polling and command requests should not lock out the operator.
    state.auth_rate_limiters.check(&client_ip)?;
    Err(StatusCode::UNAUTHORIZED)
}
