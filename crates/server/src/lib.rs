//! RESTful API server — routes, middleware, request handling.
//!
//! Provides the core Axum [`app`] router which maps HTTP requests to the underlying
//! [`forge_storage::StorageEngine`]. TLS termination happens upstream in `forge_protocol`.

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
};
use forge_storage::StorageEngine;

/// Shared application state injected into all route handlers.
#[derive(Clone)]
pub struct AppState {
    pub engine: Arc<StorageEngine>,
}

/// Builds the master Axum router containing all ForgeDB v1 endpoints.
pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/v1/:collection", get(list_docs).post(insert_doc))
        .route(
            "/v1/:collection/:id",
            get(get_doc).patch(update_doc).delete(delete_doc),
        )
        .with_state(state)
}

/// GET /v1/:collection
/// Lists all documents in a collection.
async fn list_docs(
    State(state): State<AppState>,
    Path(collection): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    match state.engine.list(&collection) {
        Ok(docs) => Ok(Json(docs)),
        Err(e) => {
            tracing::error!("list failed: {e}");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// POST /v1/:collection
/// Inserts a new document. Body is JSON/MsgPack.
async fn insert_doc(
    State(state): State<AppState>,
    Path(collection): Path<String>,
    body: bytes::Bytes,
) -> Result<impl IntoResponse, StatusCode> {
    // For now, we generate a random ID if not provided, or expect it in the query?
    // Let's generate a naive UUID for v0.2 scaffolding.
    let id = uuid::Uuid::new_v4().to_string();

    match state.engine.insert(&collection, &id, &body) {
        Ok(_) => Ok((StatusCode::CREATED, Json(serde_json::json!({ "id": id })))),
        Err(e) => {
            tracing::error!("insert failed: {e}");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// GET /v1/:collection/:id
/// Retrieves a specific document by ID.
async fn get_doc(
    State(state): State<AppState>,
    Path((collection, id)): Path<(String, String)>,
) -> Result<impl IntoResponse, StatusCode> {
    match state.engine.get(&collection, &id) {
        Ok(Some(doc)) => {
            // Document is stored as raw bytes (MsgPack). If we want to return JSON,
            // we'll need to transcode it later. For now, just return raw bytes with generic type.
            Ok((StatusCode::OK, doc).into_response())
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
