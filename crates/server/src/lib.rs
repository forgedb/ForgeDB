//! RESTful API server — routes, middleware, request handling.
//!
//! Provides the core Axum [`app`] router which maps HTTP requests to the underlying
//! [`forge_storage::StorageEngine`]. TLS termination happens upstream in `forge_protocol`.
//!
//! The middleware pipeline runs outside-in:
//! 1. `TraceLayer` — structured request logging (method, URI, status, latency)
//! 2. `require_auth` — PASETO v4.public token verification
//! 3. `audit_logger` — outcome tracking in the immutable `_audit` table
//! 4. `require_policy` — Cedar RLS enforcement
//! 5. Route handler — the actual storage operation

use forge_query::policy::PolicyEngine;
use forge_storage::WriteSender;
use pasetors::keys::AsymmetricPublicKey;
use pasetors::version4::V4;
use std::sync::Arc;

pub mod audit;
pub mod policy;

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
};
use forge_storage::StorageEngine;
use tower_http::trace::TraceLayer;

/// Maps HTTP verbs to ForgeDB action names for Cedar and audit logging.
///
/// Lives here because both `audit.rs` and `policy.rs` need it. We map to the
/// three actions the Cedar schema actually recognizes: Read, Write, Delete.
/// POST and PATCH are both "Write" — the schema doesn't distinguish creation
/// from mutation, and honestly that keeps the policy surface smaller anyway.
pub fn map_method_to_action(method: &axum::http::Method) -> &'static str {
    match *method {
        axum::http::Method::GET => "Read",
        axum::http::Method::POST => "Write",
        axum::http::Method::PATCH | axum::http::Method::PUT => "Write",
        axum::http::Method::DELETE => "Delete",
        _ => "Unknown",
    }
}

/// Shared application state injected into all route handlers.
#[derive(Clone)]
pub struct AppState {
    pub engine: Arc<StorageEngine>,
    pub writer: WriteSender,
    pub public_key: Arc<AsymmetricPublicKey<V4>>,
    pub policy_engine: Arc<PolicyEngine>,
}

/// Builds the master Axum router containing all ForgeDB v1 endpoints.
pub fn app(state: AppState) -> Router {
    // Unauthenticated routes — health checks, future dashboard assets
    let public_routes = Router::new().route("/_/health", get(health));

    // Authenticated API routes — full middleware pipeline
    let api_routes = Router::new()
        .route("/v1/{collection}", get(list_docs).post(insert_doc))
        .route(
            "/v1/{collection}/{id}",
            get(get_doc).patch(update_doc).delete(delete_doc),
        )
        // Everything inside /v1 requires a valid PASETO token.
        // The middleware parses the Bearer header and rejects bad tokens fast.
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            policy::require_policy,
        ))
        // Audit intercepts right after Auth. It yields to Policy and then logs the outcome
        // (Permit if 200 OK, Deny if Policy kicked it out).
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            audit::audit_logger,
        ))
        .route_layer(axum::middleware::from_fn_with_state(
            state.public_key.clone(),
            forge_auth::middleware::require_auth,
        ));

    public_routes
        .merge(api_routes)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// `GET /_/health` — lightweight liveness probe.
///
/// Deliberately unauthenticated so load balancers, k8s probes, and the
/// upcoming Leptos dashboard can reach it without needing a PASETO token.
async fn health() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

/// GET /v1/:collection
/// Lists all documents in a collection as JSON objects.
///
/// Each stored MessagePack payload is transcoded to JSON on the fly.
/// Yeah, it's a full scan — pagination and cursors come in v0.3.
async fn list_docs(
    State(state): State<AppState>,
    Path(collection): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    match state.engine.list(&collection) {
        Ok(docs) => {
            // Trancscode each MessagePack payload into a JSON value so we can
            // send back a sane JSON array to the client.
            let json_docs: Vec<serde_json::Value> = docs
                .into_iter()
                .map(|(id, bytes)| {
                    let doc: serde_json::Value =
                        rmp_serde::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
                    serde_json::json!({ "id": id, "doc": doc })
                })
                .collect();
            Ok(Json(json_docs))
        }
        Err(e) => {
            tracing::error!("list failed: {e}");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// POST /v1/:collection
/// Inserts a new document. Body can be JSON or MessagePack.
/// Converts JSON into MessagePack for storage explicitly based on `Content-Type`.
///
/// Routes through the [`WriteSender`] coalescing channel so concurrent POSTs
/// share a single redbx write transaction instead of each one paying its own fsync.
async fn insert_doc(
    State(state): State<AppState>,
    Path(collection): Path<String>,
    headers: axum::http::HeaderMap,
    body: bytes::Bytes,
) -> Result<impl IntoResponse, StatusCode> {
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    // The PRD mandates MessagePack for all storage elements.
    let payload_bytes = if content_type.contains("application/json") {
        let json_val: serde_json::Value = serde_json::from_slice(&body).map_err(|e| {
            tracing::warn!("failed to parse JSON payload: {e}");
            StatusCode::BAD_REQUEST
        })?;
        rmp_serde::to_vec_named(&json_val).map_err(|e| {
            tracing::error!("failed to re-encode JSON to MessagePack: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?
    } else {
        // Assume MessagePack for "application/msgpack", "application/x-msgpack", or plain drops
        body.to_vec()
    };

    let id = uuid::Uuid::new_v4().to_string();

    // Route through the write-coalescing channel — concurrent inserts
    // get batched into a single transaction automatically.
    match state.writer.insert(&collection, &id, payload_bytes).await {
        Ok(_) => Ok((StatusCode::CREATED, Json(serde_json::json!({ "id": id })))),
        Err(e) => {
            tracing::error!("insert failed: {e}");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// GET /v1/:collection/:id
/// Retrieves a specific document by ID. Transcodes native MessagePack to JSON
/// if the client explicitly requests it via `Accept` headers.
async fn get_doc(
    State(state): State<AppState>,
    Path((collection, id)): Path<(String, String)>,
    headers: axum::http::HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    match state.engine.get(&collection, &id) {
        Ok(Some(doc)) => {
            let accept = headers
                .get(axum::http::header::ACCEPT)
                .and_then(|h| h.to_str().ok())
                .unwrap_or("");

            if accept.contains("application/json") {
                // In a perfect world we would use `serde_transcode`, but bouncing through
                // `serde_json::Value` works well enough for v0.2 scaffolding.
                let val: serde_json::Value = rmp_serde::from_slice(&doc).map_err(|e| {
                    tracing::error!("failed to read underlying msgpack: {e}");
                    StatusCode::INTERNAL_SERVER_ERROR
                })?;

                let json_bytes = serde_json::to_vec(&val).map_err(|e| {
                    tracing::error!("failed to serialize to json: {e}");
                    StatusCode::INTERNAL_SERVER_ERROR
                })?;

                Ok((
                    StatusCode::OK,
                    [(axum::http::header::CONTENT_TYPE, "application/json")],
                    json_bytes,
                )
                    .into_response())
            } else {
                Ok((
                    StatusCode::OK,
                    [(axum::http::header::CONTENT_TYPE, "application/msgpack")],
                    doc,
                )
                    .into_response())
            }
        }
        Ok(None) => Err(StatusCode::NOT_FOUND),
        Err(e) => {
            tracing::error!("get failed: {e}");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// PATCH /v1/:collection/:id
/// Partial update (placeholder).
async fn update_doc() -> impl IntoResponse {
    (
        StatusCode::NOT_IMPLEMENTED,
        "Atomic updates planned for v0.3",
    )
}

/// DELETE /v1/:collection/:id
/// Deletes a document.
async fn delete_doc(
    State(state): State<AppState>,
    Path((collection, id)): Path<(String, String)>,
) -> Result<impl IntoResponse, StatusCode> {
    match state.engine.delete(&collection, &id) {
        Ok(true) => Ok(StatusCode::NO_CONTENT),
        Ok(false) => Err(StatusCode::NOT_FOUND),
        Err(e) => {
            tracing::error!("delete failed: {e}");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Serve a single TLS stream using hyper-util and the axum router.
pub async fn serve_connection(
    stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    app: Router,
) {
    let io = hyper_util::rt::TokioIo::new(stream);

    // Convert the tower Service (axum Router) into a hyper Service
    let hyper_service = hyper_util::service::TowerToHyperService::new(app);

    if let Err(e) =
        hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
            .serve_connection_with_upgrades(io, hyper_service)
            .await
    {
        tracing::error!("Error serving connection: {e}");
    }
}
