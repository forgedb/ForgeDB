use axum::{body::Body, extract::State, http::Request, middleware::Next, response::Response};
use forge_auth::TokenClaims;
use forge_types::{AuditEntry, Outcome};

use crate::AppState;

/// Maps HTTP verbs to ForgeDB actions for the audit log.
fn map_http_method_to_action(method: &axum::http::Method) -> &'static str {
    match *method {
        axum::http::Method::GET => "Read",
        axum::http::Method::POST => "Create",
        axum::http::Method::PATCH | axum::http::Method::PUT => "Update",
        axum::http::Method::DELETE => "Delete",
        _ => "Unknown",
    }
}

/// Middleware that intercepts requests after authentication to seamlessly
/// track the outcome of the request in the immutable `_audit` table.
/// By executing 'outside-in', it captures any HTTP 403 Forbidden errors triggered
/// from the Cedar policy engine within inner layers, ensuring accurate Permit/Deny logging.
pub async fn audit_logger(
    State(state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let method = req.method().clone();
    let uri = req.uri().path().to_string();

    let claims = req.extensions().get::<TokenClaims>().cloned();
    let principal = claims
        .map(|c| c.sub.clone())
        .unwrap_or_else(|| "anonymous".to_string());

    let action = map_http_method_to_action(&method);

    // Yield to the inner layers (specifically, policy enforcement and core storage APIs)
    let response = next.run(req).await;

    let outcome = if response.status().is_client_error() || response.status().is_server_error() {
        Outcome::Deny
    } else {
        Outcome::Permit
    };

    let entry = AuditEntry::new(
        &principal, action, &uri, None, // We skip specific doc IDs on the catch-all for now
        outcome,
    );

    if let Err(e) = state.engine.audit_log().append(&entry) {
        tracing::error!("CRITICAL: failed to write audit log entry: {e}");
        // In highly compliant setups you might drop the response completely and return 500 here,
        // but for now, we leave it as an error log.
    }

    response
}
