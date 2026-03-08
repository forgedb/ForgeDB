use aws_lc_rs::rand::SecureRandom;
use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde::{Deserialize, Serialize};

use crate::AppState;

#[derive(Serialize)]
pub struct AuthStatus {
    pub setup_required: bool,
}

pub async fn auth_status(State(state): State<AppState>) -> impl IntoResponse {
    let setup_required = state
        .engine
        .get("_system", "admin_auth")
        .map(|o| o.is_none())
        .unwrap_or(true);
    (StatusCode::OK, Json(AuthStatus { setup_required }))
}

#[derive(Deserialize)]
pub struct SetupReq {
    pub token: String,
    pub password: String,
}

pub async fn setup(
    State(state): State<AppState>,
    Json(payload): Json<SetupReq>,
) -> Result<impl IntoResponse, StatusCode> {
    // verify token
    forge_auth::validate_token(&payload.token, &state.public_key)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    let setup_required = state
        .engine
        .get("_system", "admin_auth")
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
        "salt": hex::encode(salt)
    });
    let bytes = rmp_serde::to_vec_named(&doc).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    state
        .engine
        .insert("_system", "admin_auth", &bytes)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(StatusCode::OK)
}

#[derive(Deserialize)]
pub struct LoginReq {
    pub password: String,
}

#[derive(Serialize)]
pub struct LoginRes {
    pub token: String,
}

pub async fn login(
    State(state): State<AppState>,
    Json(payload): Json<LoginReq>,
) -> Result<impl IntoResponse, StatusCode> {
    let doc_bytes = state
        .engine
        .get("_system", "admin_auth")
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // Fallback to json decoding
    let doc: serde_json::Value = forge_storage::document::deserialize_doc(&doc_bytes)
        .unwrap_or_else(|_| serde_json::json!({}));
    let stored_hash = doc.get("hash").and_then(|h| h.as_str()).unwrap_or("");
    let stored_salt_hex = doc.get("salt").and_then(|s| s.as_str()).unwrap_or("");

    let salt = hex::decode(stored_salt_hex).unwrap_or_default();
    let mut attempt_hash_bytes = [0u8; 32];
    if !salt.is_empty() {
        aws_lc_rs::pbkdf2::derive(
            aws_lc_rs::pbkdf2::PBKDF2_HMAC_SHA256,
            std::num::NonZeroU32::new(100_000).unwrap(),
            &salt,
            payload.password.as_bytes(),
            &mut attempt_hash_bytes,
        );
    }
    let attempt_hash = hex::encode(attempt_hash_bytes);

    if stored_hash != attempt_hash || stored_hash.is_empty() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let claims = forge_auth::TokenClaims::new("admin", 30 * 24 * 3600, Some("admin".into()));
    let token = forge_auth::issue_token(&claims, &state.secret_key)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok((StatusCode::OK, Json(LoginRes { token })))
}
