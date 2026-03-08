//! Cedar policy enforcement middleware — the authorization checkpoint.
//!
//! This runs *after* the PASETO auth middleware has verified identity. It takes
//! the verified claims, maps the HTTP method to one of our three Cedar actions
//! (Read, Write, Delete), builds a Cedar request, and checks it against the
//! loaded policy set. No permit? No access. A single `forbid` overrides
//! everything — that's the whole point.

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
    let action = crate::map_method_to_action(req.method());

    let uri = req.uri().path();

    // Normalize: remove duplicate slashes and trim trailing slash
    let normalized_path = uri.split('/').filter(|s| !s.is_empty()).collect::<Vec<_>>();

    // Convert paths like "/v1/users/123" -> "users/123"
    // Keep internal system paths like "/_/schema" as is (relative to root)
    let resource = match normalized_path.as_slice() {
        ["v1", collection] => collection.to_string(),
        ["v1", collection, id] => format!("{collection}/{id}"),
        path => path.join("/"),
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
