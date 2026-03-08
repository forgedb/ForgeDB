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
    // Unauthenticated routes — health checks, schema introspection, future dashboard assets
    let public_routes = Router::new()
        .route("/_/health", get(health))
        .route("/_/schema", get(schema_info));

    // Authenticated API routes — full middleware pipeline
    let api_routes = Router::new()
        .route("/v1/{collection}", get(list_docs).post(insert_doc))
        .route(
            "/v1/{collection}/{id}",
            get(get_doc).patch(update_doc).delete(delete_doc),
        )
        .route("/v1/_query", axum::routing::post(query_docs_stub))
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

/// `GET /_/schema` — Cedar namespace introspection.
///
/// Unauthenticated endpoint that returns the structured `SchemaInfo` so the
/// Leptos dashboard can provide auto-completion for policies.
async fn schema_info() -> Result<impl IntoResponse, StatusCode> {
    match forge_query::introspect_schema() {
        Ok(info) => Ok(Json(info)),
        Err(e) => {
            tracing::error!("schema introspection failed: {e}");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// GET /v1/:collection
/// Lists all documents in a collection.
///
/// Transcodes to JSON if requested; otherwise defaults to MessagePack with named fields.
/// Yeah, it's a full scan — pagination and cursors come in v0.3 Phase B.
async fn list_docs(
    State(state): State<AppState>,
    Path(collection): Path<String>,
    headers: axum::http::HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    match state.engine.list(&collection) {
        Ok(docs) => {
            let accept = headers
                .get(axum::http::header::ACCEPT)
                .and_then(|h| h.to_str().ok())
                .unwrap_or("");

            if accept.contains("application/json") {
                let json_docs: Vec<serde_json::Value> = docs
                    .into_iter()
                    .map(|(id, bytes)| {
                        let doc: serde_json::Value =
                            rmp_serde::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
                        serde_json::json!({ "id": id, "doc": doc })
                    })
                    .collect();
                Ok((
                    StatusCode::OK,
                    [(axum::http::header::CONTENT_TYPE, "application/json")],
                    serde_json::to_vec(&json_docs).unwrap_or_default(),
                )
                    .into_response())
            } else {
                // For MessagePack, we need to wrap the internal documents in a structured array.
                // We use serde_json::Value as an intermediate to deserialize the inner doc and
                // re-serialize as named msgpack, avoiding strict struct typing.
                let mut wrapper = Vec::new();
                for (id, bytes) in docs {
                    if let Ok(val) = rmp_serde::from_slice::<serde_json::Value>(&bytes) {
                        wrapper.push(serde_json::json!({ "id": id, "doc": val }));
                    }
                }
                let resp_bytes =
                    forge_storage::document::serialize_doc_named(&wrapper).map_err(|e| {
                        tracing::error!("failed to serialize list to msgpack: {e}");
                        StatusCode::INTERNAL_SERVER_ERROR
                    })?;

                Ok((
                    StatusCode::OK,
                    [(axum::http::header::CONTENT_TYPE, "application/msgpack")],
                    resp_bytes,
                )
                    .into_response())
            }
        }
        Err(e) => {
            tracing::error!("list failed: {e}");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// POST /v1/:collection
/// Inserts a new document. Body can be JSON or MessagePack.
/// Converts to compact MessagePack for storage explicitly based on `Content-Type`.
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

    // Read inbound payload into a generic Value map, then encode as compact MessagePack for disk
    let payload_bytes = if content_type.contains("application/json") {
        let json_val: serde_json::Value = serde_json::from_slice(&body).map_err(|e| {
            tracing::warn!("failed to parse JSON payload: {e}");
            StatusCode::BAD_REQUEST
        })?;
        forge_storage::document::serialize_doc(&json_val).map_err(|e| {
            tracing::error!("failed to re-encode JSON to MessagePack: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?
    } else {
        // Even if they send MessagePack, we re-encode it to ensure it's compact internal format
        // and physically valid. Don't trust raw bytes from the wire directly onto disk.
        let val: serde_json::Value =
            forge_storage::document::deserialize_doc(&body).map_err(|e| {
                tracing::warn!("failed to parse inbound MessagePack: {e}");
                StatusCode::BAD_REQUEST
            })?;
        forge_storage::document::serialize_doc(&val).map_err(|e| {
            tracing::error!("failed to finalize MessagePack: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?
    };

    let id = uuid::Uuid::new_v4().to_string();

    match state.writer.insert(&collection, &id, payload_bytes).await {
        Ok(_) => {
            // Respect Accept headers even for CREATED responses
            let accept = headers
                .get(axum::http::header::ACCEPT)
                .and_then(|h| h.to_str().ok())
                .unwrap_or("");

            let response_body = serde_json::json!({ "id": id });

            if accept.contains("application/json") {
                Ok((
                    StatusCode::CREATED,
                    [(axum::http::header::CONTENT_TYPE, "application/json")],
                    serde_json::to_vec(&response_body).unwrap_or_default(),
                )
                    .into_response())
            } else {
                let msg_bytes = forge_storage::document::serialize_doc_named(&response_body)
                    .unwrap_or_default();
                Ok((
                    StatusCode::CREATED,
                    [(axum::http::header::CONTENT_TYPE, "application/msgpack")],
                    msg_bytes,
                )
                    .into_response())
            }
        }
        Err(e) => {
            tracing::error!("insert failed: {e}");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// GET /v1/:collection/:id
/// Retrieves a specific document by ID.
/// Defaults to returning named MessagePack. Transcodes to JSON only if requested.
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

            // The underlying document is compact MessagePack. We MUST deserialize it
            // and re-serialize it so we get named fields (for MsgPack responses) or JSON.
            let val: serde_json::Value =
                forge_storage::document::deserialize_doc(&doc).map_err(|e| {
                    tracing::error!("failed to read underlying msgpack: {e}");
                    StatusCode::INTERNAL_SERVER_ERROR
                })?;

            if accept.contains("application/json") {
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
                let msg_bytes =
                    forge_storage::document::serialize_doc_named(&val).map_err(|e| {
                        tracing::error!("failed to serialize to named msgpack: {e}");
                        StatusCode::INTERNAL_SERVER_ERROR
                    })?;

                Ok((
                    StatusCode::OK,
                    [(axum::http::header::CONTENT_TYPE, "application/msgpack")],
                    msg_bytes,
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

/// POST /v1/_query
/// Safe Joins implementation (placeholder for Phase D).
async fn query_docs_stub() -> impl IntoResponse {
    (
        StatusCode::NOT_IMPLEMENTED,
        "Safe Joins landing in v0.3 Phase D",
    )
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
