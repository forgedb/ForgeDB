//! PASETO v4.public token issuance and verification.
//!
//! Tokens carry identity claims — who you are, when this expires, that sort of
//! thing. We intentionally went with v4.public (Ed25519 signatures) rather than
//! v4.local (symmetric encryption) because the public key can be freely
//! distributed. Cluster followers verify tokens without ever touching the
//! secret key. Simple, and it removes an entire class of key-distribution
//! headaches that come with symmetric schemes.
//!
//! The `Claims` struct from `pasetors` handles the heavy lifting: `iat`, `nbf`,
//! and `exp` get automatic defaults, and we layer on `sub` (user id) and
//! `iss` ("forgedb"). Custom claims like `role` ride along as additional fields.

use core::convert::TryFrom;

use pasetors::claims::{Claims, ClaimsValidationRules};
use pasetors::keys::{AsymmetricPublicKey, AsymmetricSecretKey};
use pasetors::token::UntrustedToken;
use pasetors::version4::V4;
use pasetors::{Public, public};
use serde::{Deserialize, Serialize};

use forge_types::{ForgeError, Result};

/// The "who, when, and why" baked into every ForgeDB token.
///
/// Designed to be lean — we're not trying to reinvent JWTs with fifty optional
/// fields. `sub` and `exp` are mandatory, `role` is there for policy evaluation
/// (Cedar needs to know if you're an admin or a regular user, after all).
///
/// # Examples
///
/// ```rust,no_run
/// use forge_auth::TokenClaims;
///
/// let claims = TokenClaims::new("user-42", 3600, None);
/// assert_eq!(claims.sub, "user-42");
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TokenClaims {
    /// Subject — typically the user ID or service account name.
    pub sub: String,

    /// Expiration as seconds from now. Gets converted to an RFC 3339 timestamp
    /// during token creation — pasetors handles the messy date math.
    pub exp_seconds: u64,

    /// Optional role hint for downstream policy decisions. Not enforced here;
    /// the Cedar engine is the one that actually cares about this value.
    pub role: Option<String>,
}

impl TokenClaims {
    /// Build a new set of claims. `exp_seconds` is relative — 3600 means
    /// "valid for one hour from right now."
    pub fn new(sub: impl Into<String>, exp_seconds: u64, role: Option<String>) -> Self {
        Self {
            sub: sub.into(),
            exp_seconds,
            role,
        }
    }
}

/// Signs a set of claims into a PASETO v4.public token string.
///
/// The resulting token is self-contained: anyone with the matching public key
/// can verify it, no database round-trip required. Issuer is hardcoded to
/// "forgedb" — if you're running this code, that's who you are.
///
/// # Errors
///
/// Returns [`ForgeError::Auth`] if claim construction or signing fails.
/// In practice this almost never happens unless the key is somehow invalid.
pub fn issue_token(
    token_claims: &TokenClaims,
    secret_key: &AsymmetricSecretKey<V4>,
) -> Result<String> {
    let mut claims = Claims::new().map_err(|e| ForgeError::Auth(format!("claims init: {e}")))?;

    claims
        .subject(&token_claims.sub)
        .map_err(|e| ForgeError::Auth(format!("setting subject: {e}")))?;

    claims
        .issuer("forgedb")
        .map_err(|e| ForgeError::Auth(format!("setting issuer: {e}")))?;

    // pasetors wants an RFC 3339 timestamp for expiration, so we do the
    // arithmetic ourselves. Could pull in chrono, but this is fine for now.
    let exp_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| ForgeError::Auth(format!("system clock: {e}")))?
        .as_secs()
        + token_claims.exp_seconds;

    let exp_rfc3339 = format_unix_as_rfc3339(exp_ts);
    claims
        .expiration(&exp_rfc3339)
        .map_err(|e| ForgeError::Auth(format!("setting expiration: {e}")))?;

    if let Some(ref role) = token_claims.role {
        claims
            .add_additional("role", role.clone())
            .map_err(|e| ForgeError::Auth(format!("setting role: {e}")))?;
    }

    public::sign(secret_key, &claims, None, None)
        .map_err(|e| ForgeError::Auth(format!("token signing failed: {e}")))
}

/// Verifies a PASETO v4.public token and extracts the claims.
///
/// Checks signature validity, then validates `nbf`, `iat`, `exp`, and
/// that `iss` is "forgedb". If any of those checks fail, you get an error —
/// no partial results, no "well the signature was good but it's expired."
///
/// # Errors
///
/// Returns [`ForgeError::Auth`] on signature mismatch, expiry, or claim
/// validation failure.
pub fn validate_token(token: &str, public_key: &AsymmetricPublicKey<V4>) -> Result<TokenClaims> {
    let mut rules = ClaimsValidationRules::new();
    rules.validate_issuer_with("forgedb");

    let untrusted = UntrustedToken::<Public, V4>::try_from(token)
        .map_err(|e| ForgeError::Auth(format!("token parse: {e}")))?;

    let trusted = public::verify(public_key, &untrusted, &rules, None, None)
        .map_err(|e| ForgeError::Auth(format!("token verification: {e}")))?;

    let payload = trusted
        .payload_claims()
        .ok_or_else(|| ForgeError::Auth("token has no payload claims".into()))?;

    // Pull out the fields we care about. `sub` is mandatory.
    let sub = payload
        .get_claim("sub")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ForgeError::Auth("missing 'sub' claim".into()))?
        .to_string();

    let role = payload
        .get_claim("role")
        .and_then(|v| v.as_str())
        .map(String::from);

    // exp_seconds doesn't matter post-verification (the library already checked
    // it), but we stash 0 to keep the struct populated.
    Ok(TokenClaims {
        sub,
        exp_seconds: 0,
        role,
    })
}

/// Quick-and-dirty UTC timestamp formatter. No dependencies, no allocations
/// beyond the string itself. Good enough for PASETO's RFC 3339 requirement.
fn format_unix_as_rfc3339(secs: u64) -> String {
    // Days per month in a non-leap year. February gets patched below.
    const DAYS_IN_MONTH: [u64; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

    let days_total = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Walk years from 1970 forward.
    let mut year = 1970u64;
    let mut remaining_days = days_total;
    loop {
        let days_in_year = if is_leap(year) { 366 } else { 365 };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        year += 1;
    }

    let mut month = 0usize;
    let mut days_in_months = DAYS_IN_MONTH;
    if is_leap(year) {
        days_in_months[1] = 29;
    }
    while month < 11 && remaining_days >= days_in_months[month] {
        remaining_days -= days_in_months[month];
        month += 1;
    }

    let day = remaining_days + 1;
    let month_1 = month as u64 + 1;

    format!("{year:04}-{month_1:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}+00:00")
}

fn is_leap(y: u64) -> bool {
    y.is_multiple_of(4) && (!y.is_multiple_of(100) || y.is_multiple_of(400))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::generate_keypair;

    #[test]
    fn round_trip_encode_decode() {
        let kp = generate_keypair().unwrap();
        let claims = TokenClaims::new("user-99", 3600, Some("admin".into()));

        let token_str = issue_token(&claims, &kp.secret).unwrap();
        let decoded = validate_token(&token_str, &kp.public).unwrap();

        assert_eq!(decoded.sub, "user-99");
        assert_eq!(decoded.role, Some("admin".into()));
    }

    #[test]
    fn token_without_role_roundtrips() {
        let kp = generate_keypair().unwrap();
        let claims = TokenClaims::new("svc-account", 3600, None);

        let token_str = issue_token(&claims, &kp.secret).unwrap();
        let decoded = validate_token(&token_str, &kp.public).unwrap();

        assert_eq!(decoded.sub, "svc-account");
        assert!(decoded.role.is_none());
    }

    #[test]
    fn expired_token_is_rejected() {
        let kp = generate_keypair().unwrap();
        // Zero seconds from now — by the time we verify, it's already expired.
        let claims = TokenClaims::new("user-1", 0, None);
        let token_str = issue_token(&claims, &kp.secret).unwrap();

        // Tiny sleep to guarantee the token is past its expiry.
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let result = validate_token(&token_str, &kp.public);
        assert!(result.is_err(), "expired token should be rejected");
    }

    #[test]
    fn tampered_token_is_rejected() {
        let kp = generate_keypair().unwrap();
        let claims = TokenClaims::new("user-1", 3600, None);
        let mut token_str = issue_token(&claims, &kp.secret).unwrap();

        // Flip the last character — that's deep in the signature.
        let last = token_str.pop().unwrap();
        let replacement = if last == 'A' { 'B' } else { 'A' };
        token_str.push(replacement);

        let result = validate_token(&token_str, &kp.public);
        assert!(result.is_err(), "tampered token must be rejected");
    }

    #[test]
    fn wrong_public_key_rejects() {
        let kp1 = generate_keypair().unwrap();
        let kp2 = generate_keypair().unwrap();
        let claims = TokenClaims::new("user-1", 3600, None);

        let token_str = issue_token(&claims, &kp1.secret).unwrap();
        // Verify with the wrong key — should fail.
        let result = validate_token(&token_str, &kp2.public);
        assert!(result.is_err(), "wrong public key must reject the token");
    }

    #[test]
    fn rfc3339_formatter_produces_valid_output() {
        // 2024-01-01T00:00:00+00:00 = 1704067200 unix
        let formatted = format_unix_as_rfc3339(1704067200);
        assert_eq!(formatted, "2024-01-01T00:00:00+00:00");
    }
}
