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
        .route(
            "/v1/_indexes/{collection}",
            axum::routing::post(create_index),
        )
        .route(
            "/v1/_indexes/{collection}/{field}",
            axum::routing::delete(drop_index),
        )
        .route("/v1/_query", axum::routing::post(query_docs))
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
/// Lists documents in a collection, chunked via cursor-based pagination.
///
/// Query params: `cursor` (string), `limit` (integer).
/// Defaults to returning MessagePack. Transcodes to JSON only if requested.
async fn list_docs(
    State(state): State<AppState>,
    Path(collection): Path<String>,
    axum::extract::Query(params): axum::extract::Query<forge_types::pagination::PaginationParams>,
    axum::extract::Extension(claims): axum::extract::Extension<forge_auth::TokenClaims>,
    headers: axum::http::HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    let limit = params.limit.unwrap_or(50).clamp(1, 100) as usize;
    let mut current_cursor = params.cursor.clone();

    let mut where_filter = None;
    for (k, v) in &params.query_filters {
        if k.starts_with("where[") && k.ends_with("]") {
            let field = &k[6..k.len() - 1];
            where_filter = Some((field, v));
            break;
        }
    }

    let msgpack_val = if let Some((_, val_str)) = where_filter {
        let v = match serde_json::from_str::<serde_json::Value>(val_str) {
            Ok(j) => forge_storage::document::serialize_doc(&j).unwrap_or_default(),
            Err(_) => forge_storage::document::serialize_doc(&serde_json::Value::String(
                val_str.to_string(),
            ))
            .unwrap_or_default(),
        };
        Some(v)
    } else {
        None
    };

    let principal = &claims.sub;
    let action = "Read";

    let mut valid_docs = Vec::new();
    let mut total_scanned = 0;
    const MAX_SCAN_LIMIT: usize = 1000;
    let mut last_scanned_id = None;

    while valid_docs.len() < limit && total_scanned < MAX_SCAN_LIMIT {
        let fetch_limit = std::cmp::min(MAX_SCAN_LIMIT - total_scanned, limit);

        let query_result = match where_filter {
            Some((field, _)) => state.engine.lookup_by_index(
                &collection,
                field,
                msgpack_val.as_ref().unwrap(),
                current_cursor.as_deref(),
                fetch_limit,
            ),
            None => {
                state
                    .engine
                    .list_paginated(&collection, current_cursor.as_deref(), fetch_limit)
            }
        }
        .map_err(|e| {
            tracing::error!("list_paginated failed: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        let (docs, next_cursor) = query_result;
        let fetched_len = docs.len();

        if fetched_len == 0 {
            break;
        }

        total_scanned += fetched_len;

        for (id, bytes) in docs {
            let resource = format!("{}/{}", collection, id);
            let auth_ctx = forge_query::context::AuthContext::new(principal, action, &resource);

            if state.policy_engine.check_permit(&auth_ctx).is_ok() {
                valid_docs.push((id.clone(), bytes));
                if valid_docs.len() == limit {
                    last_scanned_id = Some(id);
                    break;
                }
            }
            last_scanned_id = Some(id);
        }

        current_cursor = next_cursor.clone();
        if next_cursor.is_none() {
            break;
        }
    }

    let next_cursor = if valid_docs.len() == limit || current_cursor.is_some() {
        last_scanned_id.or(current_cursor)
    } else {
        None
    };

    let accept = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    if accept.contains("application/json") {
        let json_docs: Vec<serde_json::Value> = valid_docs
            .into_iter()
            .map(|(id, bytes)| {
                let doc: serde_json::Value =
                    rmp_serde::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
                serde_json::json!({ "id": id, "doc": doc })
            })
            .collect();

        let has_more = next_cursor.is_some();
        let response = forge_types::pagination::PaginatedResponse {
            data: json_docs,
            next_cursor: next_cursor.clone(),
            has_more,
        };

        Ok((
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            serde_json::to_vec(&response).unwrap_or_default(),
        )
            .into_response())
    } else {
        let mut wrapper = Vec::with_capacity(valid_docs.len());
        for (id, bytes) in valid_docs {
            if let Ok(val) = rmp_serde::from_slice::<serde_json::Value>(&bytes) {
                wrapper.push(serde_json::json!({ "id": id, "doc": val }));
            }
        }

        let has_more = next_cursor.is_some();
        let response = forge_types::pagination::PaginatedResponse {
            data: wrapper,
            next_cursor,
            has_more,
        };

        let resp_bytes = forge_storage::document::serialize_doc_named(&response).map_err(|e| {
            tracing::error!("failed to serialize paginated list to msgpack: {e}");
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

/// Helper function to execute local BFS N+1 joins directly on the B-Tree memory maps.
fn process_joins(
    engine: &forge_storage::StorageEngine,
    policy_engine: &forge_query::policy::PolicyEngine,
    principal: &str,
    parent_docs: &mut [serde_json::Value],
    joins: &std::collections::HashMap<String, forge_types::query::JoinNode>,
) {
    for (join_key, node) in joins {
        let coll_ctx = forge_query::context::AuthContext::new(principal, "Read", &node.collection);
        if policy_engine.check_permit(&coll_ctx).is_err() {
            tracing::warn!("Join denied at collection level: {}", node.collection);
            continue;
        }

        for parent in parent_docs.iter_mut() {
            let parent_obj = if let Some(o) = parent.as_object_mut() {
                o
            } else {
                continue;
            };

            let doc_obj = parent_obj.get("doc").and_then(|d| d.as_object());

            let on_val = if node.on == "id" {
                parent_obj.get("id").cloned()
            } else {
                doc_obj.and_then(|d| d.get(&node.on).cloned())
            };

            let mut joined_records = Vec::new();

            if let Some(on_v) = on_val {
                if node.target == "id" {
                    if let Some(target_id) = on_v.as_str()
                        && let Ok(Some(bytes)) = engine.get(&node.collection, target_id)
                        && let Ok(doc) = rmp_serde::from_slice::<serde_json::Value>(&bytes)
                    {
                        let doc_ctx = forge_query::context::AuthContext::new(
                            principal,
                            "Read",
                            format!("{}/{}", node.collection, target_id),
                        );
                        if policy_engine.check_permit(&doc_ctx).is_ok() {
                            joined_records.push(serde_json::json!({
                                "id": target_id,
                                "doc": doc,
                                "_joins": serde_json::json!({})
                            }));
                        }
                    }
                } else {
                    let msgpack_val =
                        forge_storage::document::serialize_doc(&on_v).unwrap_or_default();
                    if let Ok((matches, _)) = engine.lookup_by_index(
                        &node.collection,
                        &node.target,
                        &msgpack_val,
                        None,
                        100,
                    ) {
                        for (j_id, j_bytes) in matches {
                            let doc_ctx = forge_query::context::AuthContext::new(
                                principal,
                                "Read",
                                format!("{}/{}", node.collection, j_id),
                            );
                            if policy_engine.check_permit(&doc_ctx).is_ok()
                                && let Ok(doc) =
                                    rmp_serde::from_slice::<serde_json::Value>(&j_bytes)
                            {
                                joined_records.push(serde_json::json!({
                                    "id": j_id,
                                    "doc": doc,
                                    "_joins": serde_json::json!({})
                                }));
                            }
                        }
                    }
                }
            }

            if !node.joins.is_empty() && !joined_records.is_empty() {
                process_joins(
                    engine,
                    policy_engine,
                    principal,
                    &mut joined_records,
                    &node.joins,
                );
            }

            if let Some(joins_map) = parent_obj.get_mut("_joins").and_then(|j| j.as_object_mut()) {
                joins_map.insert(join_key.clone(), serde_json::Value::Array(joined_records));
            }
        }
    }
}

/// POST /v1/_query
/// Executes a complex traversal of relation trees locally inside memory, producing deeply
/// nested and securely validated Join payloads in < 1ms without explicit SQL syntax.
async fn query_docs(
    State(state): State<AppState>,
    axum::extract::Extension(claims): axum::extract::Extension<forge_auth::TokenClaims>,
    axum::Json(query): axum::Json<forge_types::query::JoinQuery>,
) -> Result<impl IntoResponse, StatusCode> {
    if let Err(e) = query.validate() {
        tracing::warn!("Invalid join query: {e}");
        return Err(StatusCode::BAD_REQUEST);
    }

    let principal = &claims.sub;
    let action = "Read";

    let root_ctx = forge_query::context::AuthContext::new(principal, action, &query.collection);
    if state.policy_engine.check_permit(&root_ctx).is_err() {
        tracing::warn!("Query denied at root collection: {}", query.collection);
        return Err(StatusCode::FORBIDDEN);
    }

    let limit = query.resolved_limit();
    let mut current_cursor = query.cursor.clone();

    let mut valid_docs = Vec::new();
    let mut total_scanned = 0;
    const MAX_SCAN_LIMIT: usize = 1000;
    let mut last_scanned_id = None;

    let msgpack_val = if let Some((_, v)) = query.filter.iter().next() {
        Some(forge_storage::document::serialize_doc(v).unwrap_or_default())
    } else {
        None
    };

    while valid_docs.len() < limit && total_scanned < MAX_SCAN_LIMIT {
        let fetch_limit = std::cmp::min(MAX_SCAN_LIMIT - total_scanned, limit);

        let query_result = if let Some((k, _)) = query.filter.iter().next() {
            state.engine.lookup_by_index(
                &query.collection,
                k,
                msgpack_val.as_ref().unwrap(),
                current_cursor.as_deref(),
                fetch_limit,
            )
        } else {
            state
                .engine
                .list_paginated(&query.collection, current_cursor.as_deref(), fetch_limit)
        }
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let (docs, next_cursor) = query_result;
        let fetched_len = docs.len();

        if fetched_len == 0 {
            break;
        }

        total_scanned += fetched_len;

        for (id, bytes) in docs {
            let resource = format!("{}/{}", query.collection, id);
            let auth_ctx = forge_query::context::AuthContext::new(principal, action, &resource);

            if state.policy_engine.check_permit(&auth_ctx).is_ok() {
                valid_docs.push((id.clone(), bytes));
                if valid_docs.len() == limit {
                    last_scanned_id = Some(id);
                    break;
                }
            }
            last_scanned_id = Some(id);
        }

        current_cursor = next_cursor.clone();
        if next_cursor.is_none() {
            break;
        }
    }

    let next_cursor = if valid_docs.len() == limit || current_cursor.is_some() {
        last_scanned_id.or(current_cursor)
    } else {
        None
    };

    let mut root_docs: Vec<serde_json::Value> = valid_docs
        .into_iter()
        .map(|(id, bytes)| {
            let doc: serde_json::Value =
                rmp_serde::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
            serde_json::json!({
                "id": id,
                "doc": doc,
                "_joins": serde_json::json!({})
            })
        })
        .collect();

    process_joins(
        &state.engine,
        &state.policy_engine,
        principal,
        &mut root_docs,
        &query.joins,
    );

    let has_more = next_cursor.is_some();
    let response = forge_types::pagination::PaginatedResponse {
        data: root_docs,
        next_cursor,
        has_more,
    };

    Ok((
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        serde_json::to_vec(&response).unwrap_or_default(),
    ))
}

/// PATCH /v1/:collection/:id
/// Partial atomic update using RFC 7396 JSON Merge Patch semantics.
///
/// Converts the inbound patch (JSON or MsgPack) to a generic `Value`, reads the
/// current document, merges the fields atomically, and saves it.
/// Returns the updated document.
async fn update_doc(
    State(state): State<AppState>,
    Path((collection, id)): Path<(String, String)>,
    headers: axum::http::HeaderMap,
    body: bytes::Bytes,
) -> Result<impl IntoResponse, StatusCode> {
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    // Deserialize inbound patch
    let patch_val: serde_json::Value = if content_type.contains("application/json") {
        serde_json::from_slice(&body).map_err(|e| {
            tracing::warn!("failed to parse JSON patch: {e}");
            StatusCode::BAD_REQUEST
        })?
    } else {
        forge_storage::document::deserialize_doc(&body).map_err(|e| {
            tracing::warn!("failed to parse MessagePack patch: {e}");
            StatusCode::BAD_REQUEST
        })?
    };

    // Serialize it back to bytes for the merge_fn signature (it expects `&[u8]`)
    // Actually, we can just close over `patch_val` and ignore the `patch_bytes` param
    // to avoid an extra alloc, or pass an empty slice. We'll pass the patch bytes to
    // appease the signature, but use our decoded struct.

    // However, the signature is `engine.update_doc(..., patch: &[u8], merge_fn)`
    // So let's serialize the patch explicitly for the call.
    let patch_bytes = forge_storage::document::serialize_doc(&patch_val).map_err(|e| {
        tracing::error!("failed to serialize patch intermediate: {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    match state.engine.update_doc(
        &collection,
        &id,
        &patch_bytes,
        |existing_bytes, _patch_bytes| {
            // Read the existing document into a mutable serde_json::Value
            let mut doc: serde_json::Value =
                forge_storage::document::deserialize_doc(existing_bytes).map_err(|e| {
                    tracing::error!("corrupted storage doc during update: {e}");
                    forge_types::ForgeError::Storage(redbx::Error::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Storage corruption",
                    )))
                })?;

            // Apply the RFC 7396 Merge Patch
            json_patch::merge(&mut doc, &patch_val);

            // Re-encode back to compact internal representation
            let final_bytes = forge_storage::document::serialize_doc(&doc).map_err(|e| {
                tracing::error!("failed to re-encode merged doc to msgpack: {e}");
                forge_types::ForgeError::Storage(redbx::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Re-encoding failed",
                )))
            })?;

            Ok(final_bytes)
        },
    ) {
        Ok(merged_bytes) => {
            let accept = headers
                .get(axum::http::header::ACCEPT)
                .and_then(|h| h.to_str().ok())
                .unwrap_or("");

            let val: serde_json::Value = forge_storage::document::deserialize_doc(&merged_bytes)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

            let response_body = serde_json::json!({ "id": id, "doc": val });

            if accept.contains("application/json") {
                let json_bytes = serde_json::to_vec(&response_body).unwrap_or_default();
                Ok((
                    StatusCode::OK,
                    [(axum::http::header::CONTENT_TYPE, "application/json")],
                    json_bytes,
                )
                    .into_response())
            } else {
                let msg_bytes = forge_storage::document::serialize_doc_named(&response_body)
                    .unwrap_or_default();
                Ok((
                    StatusCode::OK,
                    [(axum::http::header::CONTENT_TYPE, "application/msgpack")],
                    msg_bytes,
                )
                    .into_response())
            }
        }
        Err(forge_types::ForgeError::Storage(redbx::Error::Io(e)))
            if e.kind() == std::io::ErrorKind::NotFound =>
        {
            Err(StatusCode::NOT_FOUND)
        }
        Err(e) => {
            tracing::error!("update failed: {e}");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
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

/// POST /v1/_indexes/:collection
/// Creates a secondary index for the collection based on the field provided in the JSON body.
async fn create_index(
    State(state): State<AppState>,
    Path(collection): Path<String>,
    axum::Json(payload): axum::Json<serde_json::Value>,
) -> Result<impl IntoResponse, StatusCode> {
    let field = payload
        .get("field")
        .and_then(|v| v.as_str())
        .ok_or(StatusCode::BAD_REQUEST)?;

    state.engine.create_index(&collection, field).map_err(|e| {
        tracing::error!("create_index failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(StatusCode::CREATED)
}

/// DELETE /v1/_indexes/:collection/:field
/// Drops a secondary index natively from the core engine.
async fn drop_index(
    State(state): State<AppState>,
    Path((collection, field)): Path<(String, String)>,
) -> Result<impl IntoResponse, StatusCode> {
    state.engine.drop_index(&collection, &field).map_err(|e| {
        tracing::error!("drop_index failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(StatusCode::NO_CONTENT)
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
