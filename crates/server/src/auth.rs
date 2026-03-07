use axum::{
    extract::{Request, State},
    http::{StatusCode, header::AUTHORIZATION},
    middleware::Next,
    response::{IntoResponse, Response},
};
use forge_auth::validate_bearer_token;

use crate::AppState;

pub async fn require_auth(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, Response> {
    let auth_header = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|h| h.to_str().ok());

    match auth_header {
        Some(header_val) => match validate_bearer_token(header_val, &state.public_key) {
            Ok(claims) => {
                req.extensions_mut().insert(claims);
                Ok(next.run(req).await)
            }
            Err(e) => {
                tracing::warn!("authentication failed: {e}");
                Err((StatusCode::UNAUTHORIZED, "Invalid Token").into_response())
            }
        },
        None => {
            tracing::warn!("missing Authorization header");
            Err((StatusCode::UNAUTHORIZED, "Missing Authorization Header").into_response())
        }
    }
}
