//! Authentication API handlers — setup, login, and user management.
//!
//! These are the "before you get a token" endpoints. The happy path is dead simple:
//! POST a username/password, get a PASETO token back. Everything else here is
//! mostly defense — PBKDF2 derivation, constant-time verification, role checks.
//!
//! # Security model
//!
//! Passwords are stored as `PBKDF2-HMAC-SHA256` derived bytes (100k iterations),
//! with a fresh 16-byte random salt per user. Verification uses `aws_lc_rs::pbkdf2::verify()`
//! which does the comparison in constant time — no timing leaks, even across the hex boundary.
//!
//! The setup endpoint requires the operator's PASETO admin token to bootstrap.
//! This prevents drive-by setup attacks on a freshly initialized DB.

use aws_lc_rs::rand::SecureRandom;
use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde::{Deserialize, Serialize};

use crate::AppState;

/// Response shape for `GET /_/auth/status`.
#[derive(Serialize)]
pub struct AuthStatus {
    /// `true` if no admin user has been set up yet — the TUI/client should
    /// redirect to the setup flow in this case.
    pub setup_required: bool,
}

/// `GET /_/auth/status` — tells callers if first-time setup is needed.
///
/// Intentionally unauthenticated. The TUI calls this on startup to decide
/// whether to show the setup screen or the login screen. No sensitive data
/// leaks here — we only return a boolean.
pub async fn auth_status(State(state): State<AppState>) -> impl IntoResponse {
    let setup_required = state
        .engine
        .get("_users", "admin")
        .map(|o| o.is_none())
        .unwrap_or(true);
    (StatusCode::OK, Json(AuthStatus { setup_required }))
}

/// `POST /_/auth/setup` — one-time admin bootstrap.
///
/// Can only succeed once — if an admin record already exists, this returns `400`.
/// Requires the server-issued initial PASETO token (printed on startup) to prevent
/// anyone from just walking in and setting their own admin password.
#[derive(Deserialize)]
pub struct SetupReq {
    /// The initial admin token printed by `forgedb serve`. This proves the person
    /// setting up the DB has access to the server console.
    pub token: String,
    /// The new admin password. Hashed with PBKDF2 before storage — never stored raw.
    pub password: String,
}

pub async fn setup(
    State(state): State<AppState>,
    Json(payload): Json<SetupReq>,
) -> Result<impl IntoResponse, StatusCode> {
    // Validate the bootstrap token first — if this fails, nothing else runs.
    forge_auth::validate_token(&payload.token, &state.public_key)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    let setup_required = state
        .engine
        .get("_users", "admin")
        .map(|o| o.is_none())
        .unwrap_or(true);
    if !setup_required {
        return Err(StatusCode::BAD_REQUEST);
    }

    let mut salt = [0u8; 16];
    aws_lc_rs::rand::SystemRandom::new()
        .fill(&mut salt)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut hash_bytes = [0u8; 32];
    aws_lc_rs::pbkdf2::derive(
        aws_lc_rs::pbkdf2::PBKDF2_HMAC_SHA256,
        std::num::NonZeroU32::new(100_000).unwrap(),
        &salt,
        payload.password.as_bytes(),
        &mut hash_bytes,
    );

    let doc = serde_json::json!({
        "hash": hex::encode(hash_bytes),
        "salt": hex::encode(salt),
        "role": "admin"
    });
    let bytes = rmp_serde::to_vec_named(&doc).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    state
        .engine
        .insert("_users", "admin", &bytes)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(StatusCode::OK)
}

/// Request body for `POST /_/auth/login`.
#[derive(Deserialize)]
pub struct LoginReq {
    pub username: String,
    pub password: String,
}

/// Successful login response — just the token, nothing else.
#[derive(Serialize)]
pub struct LoginRes {
    pub token: String,
}

/// `POST /_/auth/login` — password verification and token issuance.
///
/// Looks up the user record, decodes the stored salt, then calls
/// `aws_lc_rs::pbkdf2::verify()` which re-derives the key and compares it
/// in constant time. This avoids the classic timing-side-channel that comes
/// from naively comparing hex strings with `!=`.
///
/// Returns a 30-day PASETO v4.public token on success. The 30-day window is
/// intentional for developer ergonomics — production deployments can tighten
/// this by tweaking `exp_seconds` in the claims.
pub async fn login(
    State(state): State<AppState>,
    Json(payload): Json<LoginReq>,
) -> Result<impl IntoResponse, StatusCode> {
    let doc_bytes = state
        .engine
        .get("_users", &payload.username)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let doc: serde_json::Value = forge_storage::document::deserialize_doc(&doc_bytes)
        .unwrap_or_else(|_| serde_json::json!({}));

    let stored_hash_hex = doc.get("hash").and_then(|h| h.as_str()).unwrap_or("");
    let stored_salt_hex = doc.get("salt").and_then(|s| s.as_str()).unwrap_or("");

    // Bail out early if either hex field is missing — these records are corrupt
    // or somehow pre-date the proper setup flow. Don't let them in.
    if stored_hash_hex.is_empty() || stored_salt_hex.is_empty() {
        tracing::warn!(
            username = %payload.username,
            "login rejected: malformed user record (missing hash or salt)"
        );
        return Err(StatusCode::UNAUTHORIZED);
    }

    let salt = hex::decode(stored_salt_hex).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let stored_hash_bytes = hex::decode(stored_hash_hex).map_err(|_| StatusCode::UNAUTHORIZED)?;

    // `pbkdf2::verify` re-derives the key from the given password + salt and
    // compares it to `stored_hash_bytes` in constant time. This is the correct
    // way to do this — string comparison on hex would leak timing info.
    let verify_result = aws_lc_rs::pbkdf2::verify(
        aws_lc_rs::pbkdf2::PBKDF2_HMAC_SHA256,
        std::num::NonZeroU32::new(100_000).unwrap(),
        &salt,
        payload.password.as_bytes(),
        &stored_hash_bytes,
    );

    if verify_result.is_err() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let role = doc.get("role").and_then(|r| r.as_str()).unwrap_or("user");
    let claims =
        forge_auth::TokenClaims::new(&payload.username, 30 * 24 * 3600, Some(role.into()));
    let token = forge_auth::issue_token(&claims, &state.secret_key)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok((StatusCode::OK, Json(LoginRes { token })))
}

/// Request body for `POST /_/auth/users`.
#[derive(Deserialize)]
pub struct CreateUserReq {
    pub username: String,
    pub password: String,
}

/// `POST /_/auth/users` — admin-only user creation.
///
/// Requires the caller to have `role: "admin"` in their PASETO token.
/// New users get `role: "user"` — there's no way to self-promote through
/// this endpoint.
pub async fn create_user(
    State(state): State<AppState>,
    axum::extract::Extension(claims): axum::extract::Extension<forge_auth::TokenClaims>,
    Json(payload): Json<CreateUserReq>,
) -> Result<impl IntoResponse, StatusCode> {
    if claims.role.as_deref() != Some("admin") {
        return Err(StatusCode::FORBIDDEN);
    }

    // Reject blank usernames — the storage key would be empty, which is ugly.
    if payload.username.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let mut salt = [0u8; 16];
    aws_lc_rs::rand::SystemRandom::new()
        .fill(&mut salt)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut hash_bytes = [0u8; 32];
    aws_lc_rs::pbkdf2::derive(
        aws_lc_rs::pbkdf2::PBKDF2_HMAC_SHA256,
        std::num::NonZeroU32::new(100_000).unwrap(),
        &salt,
        payload.password.as_bytes(),
        &mut hash_bytes,
    );

    let doc = serde_json::json!({
        "hash": hex::encode(hash_bytes),
        "salt": hex::encode(salt),
        "role": "user"
    });
    let bytes = rmp_serde::to_vec_named(&doc).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    state
        .engine
        .insert("_users", &payload.username, &bytes)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(StatusCode::CREATED)
}
