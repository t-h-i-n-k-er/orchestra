//! Bearer-token authentication middleware. Supports multi-operator lookup
//! with constant-time comparison, falling back to the legacy admin token.

use axum::{
    extract::State,
    http::{header, Request, StatusCode},
    middleware::Next,
    response::Response,
};
use std::sync::Arc;
use subtle::ConstantTimeEq;

use crate::state::AppState;

/// Identity of the authenticated operator, attached as a request extension.
#[derive(Clone)]
pub struct AuthenticatedUser(pub String);

pub async fn require_bearer(
    State(state): State<Arc<AppState>>,
    mut req: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
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
