use axum::{
    body::Body,
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use forge_auth::TokenClaims;
use forge_query::context::AuthContext;

use crate::AppState;

/// Maps HTTP verbs to ForgeDB actions for Cedar evaluation.
fn map_http_method_to_action(method: &axum::http::Method) -> &'static str {
    match *method {
        axum::http::Method::GET => "Read",
        axum::http::Method::POST => "Create",
        axum::http::Method::PATCH | axum::http::Method::PUT => "Update",
        axum::http::Method::DELETE => "Delete",
        _ => "Unknown",
    }
}

/// Middleware to enforce Cedar Row-Level Security explicitly.
///
/// Refuses access unless the exact (`principal`, `action`, `resource`) triple
/// evaluates to `permit` without any overriding `forbid` statements in the
/// system policy. This runs *after* PASETO authentication middleware finishes.
pub async fn require_policy(
    State(state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, Response> {
    let claims = req.extensions().get::<TokenClaims>().ok_or_else(|| {
        tracing::error!("policy middleware hit before auth middleware");
        (StatusCode::INTERNAL_SERVER_ERROR, "Auth Missing").into_response()
    })?;

    let principal = &claims.sub;
    let action = map_http_method_to_action(req.method());

    let uri = req.uri().path();
    let parts: Vec<&str> = uri.trim_matches('/').split('/').collect();

    // Convert paths like "/v1/users/123" -> "users/123"
    // Or "/v1/users" -> "users"
    let resource = match parts.as_slice() {
        ["v1", collection] => collection.to_string(),
        ["v1", collection, id] => format!("{collection}/{id}"),
        _ => uri.to_string(),
    };

    let auth_ctx = AuthContext::new(principal, action, &resource);

    match state.policy_engine.check_permit(&auth_ctx) {
        Ok(_) => Ok(next.run(req).await),
        Err(e) => {
            tracing::warn!("access denied by Cedar policy: {e}");
            Err((StatusCode::FORBIDDEN, "Access Denied").into_response())
        }
    }
}
