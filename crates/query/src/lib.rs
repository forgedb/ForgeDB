//! Query engine for ForgeDB (planned for full release in v0.3).
//!
//! Right now (v0.2.0), this crate is exclusively housing the Cedar RLS (Row-Level Security) policy
//! engine. I want every single document access request routed through `PolicyEngine::check_permit`
//! before it even thinks about touching the storage layer. No exceptions.
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
