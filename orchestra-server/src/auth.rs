//! Bearer-token authentication middleware. Supports multi-operator lookup
//! with constant-time comparison, falling back to the legacy admin token.
//! Includes per-IP rate limiting to prevent brute-force token attacks.

use axum::{
    extract::State,
    http::{header, Request, StatusCode},
    middleware::Next,
    response::Response,
};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use std::sync::Arc;
use subtle::ConstantTimeEq;

use crate::state::AppState;

/// Identity of the authenticated operator, attached as a request extension.
#[derive(Clone)]
pub struct AuthenticatedUser(pub String);

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

    pub fn check(&self) -> Result<(), StatusCode> {
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

pub async fn require_bearer(
    State(state): State<Arc<AppState>>,
    mut req: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    // Rate-limit authentication attempts.
    state.auth_rate_limiter.check()?;

    let header_val = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let presented = header_val.strip_prefix("Bearer ").unwrap_or("");

    // 1. Try the multi-operator store (constant-time SHA-256 hash comparison).
    if let Some(operator_id) = state.authenticate_operator(presented) {
        req.extensions_mut()
            .insert(AuthenticatedUser(operator_id));
        return Ok(next.run(req).await);
    }

    // 2. Fallback: legacy single admin token (constant-time direct comparison).
    let ok: bool = presented.as_bytes().ct_eq(state.admin_token.as_bytes()).into();
    if ok {
        req.extensions_mut()
            .insert(AuthenticatedUser("admin".into()));
        return Ok(next.run(req).await);
    }

    Err(StatusCode::UNAUTHORIZED)
}
