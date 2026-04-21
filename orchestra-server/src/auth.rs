//! Bearer-token authentication middleware. Constant-time comparison.

use axum::{
    extract::State,
    http::{header, Request, StatusCode},
    middleware::Next,
    response::Response,
};
use std::sync::Arc;
use subtle::ConstantTimeEq;

use crate::state::AppState;

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
    let expected = state.admin_token.as_bytes();

    let ok: bool = presented.as_bytes().ct_eq(expected).into();
    if !ok {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Tag the request with a synthetic user identity for audit logs.
    req.extensions_mut().insert(AuthenticatedUser("admin".into()));
    Ok(next.run(req).await)
}
