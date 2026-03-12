//! Query engine for ForgeDB (Cedar RLS + join query, fully shipped in v0.3).
//!
//! This crate houses the Cedar RLS (Row-Level Security) policy engine and the
//! join query planner. Every document access is routed through `PolicyEngine::check_permit`
//! before it touches the storage layer. No exceptions, no bypasses.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────┐     ┌────────────┐     ┌───────────┐
//! │ schema.rs├────▶│ context.rs ├────▶│ policy.rs │
//! │ (types)  │     │ (&ref ctx) │     │ (engine)  │
//! └──────────┘     └────────────┘     └───────────┘
//! ```
//!
//! # Zero Trust Default
//!
//! The `PolicyEngine` enforces a violently strict deny-by-default posture. If a query
//! runs against a collection that lacks a matching `permit` policy, access is
//! denied. A single `forbid` policy overrides any permits — period.

pub mod context;
pub mod introspect;
pub mod policy;
pub mod schema;

pub use context::AuthContext;
pub use introspect::introspect_schema;
pub use policy::PolicyEngine;
