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
        cursor_signer: std::sync::Arc::new(forge_security::CursorSigner::new(&[0u8; 32])),
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
        cursor_signer: std::sync::Arc::new(forge_security::CursorSigner::new(&[0u8; 32])),
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

    // POST a JSON document. Must explicitly ask for JSON back, otherwise
    // the v0.3 API defaults to returning MessagePack and `serde_json::from_slice` below panics.
    let insert_req = Request::builder()
        .method("POST")
        .uri("/v1/items")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json")
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

#[tokio::test]
async fn paginate_documents() {
    let (app, token, _tmp) = test_harness();

    // Insert 3 documents
    for i in 1..=3 {
        let req = Request::builder()
            .method("POST")
            .uri("/v1/items")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(format!(r#"{{"idx":{i}}}"#)))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    // Fetch page 1 (limit=2)
    let req1 = Request::builder()
        .uri("/v1/items?limit=2")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::ACCEPT, "application/json")
        .body(Body::empty())
        .unwrap();

    let resp1 = app.clone().oneshot(req1).await.unwrap();
    assert_eq!(resp1.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(resp1.into_body(), 4096).await.unwrap();
    let body: forge_types::pagination::PaginatedResponse<serde_json::Value> =
        serde_json::from_slice(&body_bytes).unwrap();

    assert_eq!(body.data.len(), 2);
    assert!(body.has_more);
    let next_cursor = body.next_cursor.expect("must have cursor");

    // Fetch page 2 (limit=2, cursor=next_cursor)
    let req2 = Request::builder()
        .uri(format!("/v1/items?limit=2&cursor={next_cursor}"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::ACCEPT, "application/json")
        .body(Body::empty())
        .unwrap();

    let resp2 = app.clone().oneshot(req2).await.unwrap();
    assert_eq!(resp2.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(resp2.into_body(), 4096).await.unwrap();
    let body: forge_types::pagination::PaginatedResponse<serde_json::Value> =
        serde_json::from_slice(&body_bytes).unwrap();

    assert_eq!(body.data.len(), 1);
    assert!(!body.has_more);
    assert_eq!(body.next_cursor, None);
}

#[tokio::test]
async fn patch_document() {
    let (app, token, _tmp) = test_harness();

    // 1. Insert original
    let insert_req = Request::builder()
        .method("POST")
        .uri("/v1/items")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json")
        .body(Body::from(r#"{"name":"test","value":42,"keep":"this"}"#))
        .unwrap();

    let insert_resp = app.clone().oneshot(insert_req).await.unwrap();
    assert_eq!(insert_resp.status(), StatusCode::CREATED);

    let body_bytes = axum::body::to_bytes(insert_resp.into_body(), 4096)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    let doc_id = body["id"].as_str().expect("id required");

    // 2. Patch document (update value, delete name, add new_field)
    let patch_req = Request::builder()
        .method("PATCH")
        .uri(format!("/v1/items/{doc_id}"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json")
        .body(Body::from(
            r#"{"value":99,"name":null,"new_field":"added"}"#,
        ))
        .unwrap();

    let patch_resp = app.clone().oneshot(patch_req).await.unwrap();
    assert_eq!(patch_resp.status(), StatusCode::OK);

    // 3. Verify changes were applied completely
    let get_req = Request::builder()
        .uri(format!("/v1/items/{doc_id}"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::ACCEPT, "application/json")
        .body(Body::empty())
        .unwrap();

    let get_resp = app.oneshot(get_req).await.unwrap();
    assert_eq!(get_resp.status(), StatusCode::OK);

    let final_bytes = axum::body::to_bytes(get_resp.into_body(), 4096)
        .await
        .unwrap();

    let final_body: serde_json::Value = serde_json::from_slice(&final_bytes).unwrap();
    println!("FINAL BODY: {}", final_body);

    let doc = &final_body;
    assert_eq!(doc["value"], 99);
    assert_eq!(doc["keep"], "this");
    assert_eq!(doc["new_field"], "added");
    assert!(
        doc.get("name").is_none(),
        "name should be deleted (null merge semantics)"
    );
}
