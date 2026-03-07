//! Bearer token extraction — the thin layer between raw HTTP headers and
//! our PASETO verification logic.
//!
//! Right now this is intentionally minimal: strip the "Bearer " prefix, hand
//! the rest to `validate_token`, done. When we add the actual HTTP server
//! (v0.3+), this'll likely grow into proper middleware with `tower::Layer`
//! or an axum extractor. For now it's a standalone function that the server
//! crate can call however it wants.

use pasetors::keys::AsymmetricPublicKey;
use pasetors::version4::V4;

use forge_types::{ForgeError, Result};

use crate::token::{TokenClaims, validate_token};

/// Extracts and validates a PASETO token from an HTTP `Authorization` header.
///
/// Expects the format `Bearer v4.public.<payload>`. Anything else — missing
/// prefix, empty string, garbage — gets a clear [`ForgeError::Auth`].
///
/// # Examples
///
/// ```rust,no_run
/// use forge_auth::validate_bearer_token;
/// # use pasetors::keys::AsymmetricPublicKey;
/// # use pasetors::version4::V4;
///
/// // Assuming you have a public key and a header value:
/// // let claims = validate_bearer_token("Bearer v4.public.abc123...", &pub_key)?;
/// ```
///
/// # Errors
///
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
