//! Bearer token extraction and Axum middleware — the actual security checkpoint.
//!
//! This isn't just a parser anymore; it's the gatekeeper. It strips the "Bearer "
//! prefix, runs the heavy cryptographic math on the PASETO v4 signature, and either
//! injects the verified claims straight into the request pipeline or kicks the client
//! out with a cold 401. I prefer rejecting bad tokens up front so downstream routes
//! (like Cedar policy enforcement) don't even have to think about malicious payloads.
//!
//! # Architecture
//!
//! - `require_auth` is an Axum `from_fn` compatible middleware.
//! - It expects an `Arc<AsymmetricPublicKey<V4>>` to be extractable from the app state.
//! - On success, it injects `TokenClaims` into the `Extensions` map. Downstream
//!   handlers or audit loggers can just pull it out like `req.extensions().get::<TokenClaims>()`.

use std::sync::Arc;

use axum::{
    extract::{Request, State},
    http::{StatusCode, header::AUTHORIZATION},
    middleware::Next,
    response::{IntoResponse, Response},
};
use pasetors::keys::AsymmetricPublicKey;
use pasetors::version4::V4;

use crate::token::{TokenClaims, validate_token};
use forge_types::{ForgeError, Result};

/// The primary Axum authentication middleware.
///
/// Looks for the `Authorization: Bearer <token>` header, validates the asymmetric
/// PASETO signature against the global public key, and embeds the resulting claims
/// into the request's extensions map. If the signature is busted, tampered, or expired,
/// it instantly returns `401 Unauthorized`.
///
/// # Note on state
/// This relies on the core application state handing over an `Arc<AsymmetricPublicKey<V4>>`.
/// Make sure your server's `AppState` derives `axum::extract::FromRef` or implements
/// it manually, otherwise you'll get gnarly trait-bound compiler splat here.
pub async fn require_auth(
    State(public_key): State<Arc<AsymmetricPublicKey<V4>>>,
    mut req: Request,
    next: Next,
) -> std::result::Result<Response, Response> {
    let auth_header = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|h| h.to_str().ok());

    match auth_header {
        Some(header_val) => match validate_bearer_token(header_val, &public_key) {
            Ok(claims) => {
                // Verified. Toss the claims in the extensions so the payload is
                // easily available for Cedar or basic endpoint handlers.
                req.extensions_mut().insert(claims);
                Ok(next.run(req).await)
            }
            Err(e) => {
                // Log what actually went wrong behind the scenes (for us),
                // but give the attacker nothing more than a generic "no".
                tracing::warn!("Rejecting token: {e}");
                Err((StatusCode::UNAUTHORIZED, "Invalid Token").into_response())
            }
        },
        None => {
            tracing::warn!("Authorization header missing entirely");
            Err((StatusCode::UNAUTHORIZED, "Missing Authorization Header").into_response())
        }
    }
}

/// The low-level standalone function that actually tears apart the string.
///
/// Expects the format `Bearer v4.public.<payload>`. Anything else gets binned with
/// a clear [`ForgeError::Auth`]. We keep this decoupled from the Axum handler
/// because sometimes it's useful to run these checks manually (and it makes unit testing easier).
///
/// # Errors
/// Returns [`ForgeError::Auth`] if the prefix is wrong or the token fails
/// verification (expired, tampered, wrong key, etc.).
pub fn validate_bearer_token(
    header_value: &str,
    public_key: &AsymmetricPublicKey<V4>,
) -> Result<TokenClaims> {
    let token = header_value.strip_prefix("Bearer ").ok_or_else(|| {
        ForgeError::Auth("missing 'Bearer ' prefix in Authorization header".into())
    })?;

    if token.is_empty() {
        return Err(ForgeError::Auth(
            "empty token after 'Bearer ' prefix".into(),
        ));
    }

    validate_token(token, public_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::generate_keypair;
    use crate::token::{TokenClaims, issue_token};

    #[test]
    fn valid_bearer_header_works() {
        let kp = generate_keypair().unwrap();
        let claims = TokenClaims::new("user-7", 3600, None);
        let token_str = issue_token(&claims, &kp.secret).unwrap();

        let header = format!("Bearer {token_str}");
        let result = validate_bearer_token(&header, &kp.public).unwrap();
        assert_eq!(result.sub, "user-7");
    }

    #[test]
    fn missing_bearer_prefix_fails() {
        let kp = generate_keypair().unwrap();
        let claims = TokenClaims::new("user-7", 3600, None);
        let token_str = issue_token(&claims, &kp.secret).unwrap();

        // No "Bearer " prefix — just the raw token.
        let result = validate_bearer_token(&token_str, &kp.public);
        assert!(result.is_err());
    }

    #[test]
    fn empty_bearer_value_fails() {
        let kp = generate_keypair().unwrap();
        let result = validate_bearer_token("Bearer ", &kp.public);
        assert!(result.is_err());
    }

    #[test]
    fn completely_empty_header_fails() {
        let kp = generate_keypair().unwrap();
        let result = validate_bearer_token("", &kp.public);
        assert!(result.is_err());
    }
}
