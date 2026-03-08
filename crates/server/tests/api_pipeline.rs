//! Integration tests for the full ForgeDB middleware pipeline.
//!
//! These exercise the real auth → audit → policy → handler chain using
//! `tower::ServiceExt::oneshot`, which gives us a proper end-to-end test
//! without needing TLS or a live TCP connection. Think of it as the
//! "does the whole thing actually hold together" sanity check.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt;

use forge_auth::keys::generate_keypair;
use forge_auth::{TokenClaims, issue_token};
use forge_query::PolicyEngine;
use forge_server::AppState;
use forge_storage::{StorageEngine, spawn_writer};
use tempfile::TempDir;

/// Spins up an in-memory ForgeDB test harness with a blanket permit policy.
fn test_harness() -> (axum::Router, String, TempDir) {
    let tmp = TempDir::new().expect("tempdir creation");
    let db_path = tmp.path().join("test.forgedb");

    let engine = StorageEngine::create(&db_path, "test-pass").expect("engine creation");
    let engine = Arc::new(engine);

    // We need to spawn the writer inside a tokio runtime, but since these tests
    // run under #[tokio::test], we can call spawn_writer directly.
    let writer = spawn_writer(engine.clone());

    let kp = generate_keypair().expect("keypair gen");
    let public_key = Arc::new(kp.public);

    // Blanket permit — allows everything, which is what we want for happy-path tests.
    let policy = PolicyEngine::new("permit(principal, action, resource);").expect("policy parse");
    let policy_engine = Arc::new(policy);

    let state = AppState {
        engine: engine.clone(),
        writer,
        public_key,
        policy_engine,
    };

    // Issue a valid token for our test user
    let claims = TokenClaims::new("test-user", 3600, Some("admin".into()));
    let token = issue_token(&claims, &kp.secret).expect("token issue");

    (forge_server::app(state), token, tmp)
}

/// Same setup but with a deny-all policy so we can test 403 responses.
fn deny_harness() -> (axum::Router, String, TempDir) {
    let tmp = TempDir::new().expect("tempdir creation");
    let db_path = tmp.path().join("test.forgedb");

    let engine = StorageEngine::create(&db_path, "test-pass").expect("engine creation");
    let engine = Arc::new(engine);
    let writer = spawn_writer(engine.clone());

    let kp = generate_keypair().expect("keypair gen");
    let public_key = Arc::new(kp.public);

    // Empty policy set  → deny by default. No permits, no access.
    let policy = PolicyEngine::new("").expect("empty policy");
    let policy_engine = Arc::new(policy);

    let state = AppState {
        engine: engine.clone(),
        writer,
        public_key,
        policy_engine,
    };

    let claims = TokenClaims::new("denied-user", 3600, None);
    let token = issue_token(&claims, &kp.secret).expect("token issue");

    (forge_server::app(state), token, tmp)
}

#[tokio::test]
async fn health_endpoint_requires_no_auth() {
    let (app, _token, _tmp) = test_harness();

    let req = Request::builder()
        .uri("/_/health")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "health should be unauthenticated"
    );
}

#[tokio::test]
async fn unauthenticated_request_returns_401() {
    let (app, _token, _tmp) = test_harness();

    // No Authorization header at all
    let req = Request::builder()
        .uri("/v1/users")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn valid_token_with_permit_policy_returns_200() {
    let (app, token, _tmp) = test_harness();

    let req = Request::builder()
        .uri("/v1/users")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "permitted user listing an empty collection should get 200"
    );
}

#[tokio::test]
async fn valid_token_with_deny_policy_returns_403() {
    let (app, token, _tmp) = deny_harness();

    let req = Request::builder()
        .uri("/v1/secrets")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "denied user should get 403 from Cedar"
    );
}

#[tokio::test]
async fn insert_and_retrieve_document() {
    let (app, token, _tmp) = test_harness();

    // POST a JSON document
    let insert_req = Request::builder()
        .method("POST")
        .uri("/v1/items")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"name":"test","value":42}"#))
        .unwrap();

    let insert_resp = app.clone().oneshot(insert_req).await.unwrap();
    assert_eq!(insert_resp.status(), StatusCode::CREATED);

    // Extract the generated ID from the response body
    let body_bytes = axum::body::to_bytes(insert_resp.into_body(), 4096)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    let doc_id = body["id"].as_str().expect("response should contain an id");

    // GET the document back
    let get_req = Request::builder()
        .uri(format!("/v1/items/{doc_id}"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::ACCEPT, "application/json")
        .body(Body::empty())
        .unwrap();

    let get_resp = app.oneshot(get_req).await.unwrap();
    assert_eq!(get_resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn garbage_bearer_token_returns_401() {
    let (app, _token, _tmp) = test_harness();

    let req = Request::builder()
        .uri("/v1/users")
        .header(header::AUTHORIZATION, "Bearer totallyFakeToken123abc")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "garbage token must be rejected"
    );
}
