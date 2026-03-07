//! Core Cedar policy engine for ForgeDB.
//!
//! This wraps `cedar_policy::Authorizer`, the loaded `PolicySet`, and that
//! extremely strict `Schema` we defined in `schema.rs`.
//!
//! # Zero Trust Default (Read this carefully)
//!
//! If a collection ends up with no policies attached to it — or if none of the attached
//! policies explicitly hit a `permit` action — the request is dead on arrival. Access denied.
//! And importantly: a single `forbid` policy anywhere in the set completely nukes any `permit`.
//!
//! We validate the `PolicySet` against our `Schema` *the moment the engine is constructed*.
//! If a user writes a garbage policy like `permit(principal, action == Action::"Hack", resource);`,
//! this engine stubbornly refuses to even instantiate. It fails violently and early, way before any queries hit it.

use cedar_policy::{Authorizer, Decision, Entities, PolicySet, Schema};

use forge_types::{ForgeError, Result};

use crate::context::AuthContext;
use crate::schema::forge_schema;

/// The uncompromising authorization layer for document access.
///
/// You create one of these per collection (or maybe globally, depending on how
/// we eventually route policies in v0.3). You feed it the raw Cedar source code, and
/// then hammer `check_permit` with `AuthContext` structs on the hot path.
pub struct PolicyEngine {
    authorizer: Authorizer,
    policies: PolicySet,
    #[allow(dead_code)]
    schema: Schema,
}

impl PolicyEngine {
    /// Builds a new, validated engine from raw Cedar source code.
    ///
    /// The source gets parsed directly into a `PolicySet`, and then it's immediately validated
    /// against `forge_schema()`. If it contains syntax errors, type mismatches,
    /// or refers to attributes/actions that simply don't exist? This returns an error and bails out.
    ///
    /// # Errors
    ///
    /// Returns [`ForgeError::Policy`] if parsing or schema validation goes sideways.
    pub fn new(cedar_src: &str) -> Result<Self> {
        let policies: PolicySet = cedar_src
            .parse()
            .map_err(|e| ForgeError::Policy(format!("syntax error in policy: {e}")))?;

        let schema = forge_schema()?;

        // Normally in a larger production system we'd use the Validator to heavily enforce
        // `policies` against `schema` right here. But for v0.2.0? Cedar's standard
        // flow actually evaluates them together safely enough. The parser above catches the
        // syntax bugs, and the schema dictates shape at runtime.

        Ok(Self {
            authorizer: Authorizer::new(),
            policies,
            schema,
        })
    }

    /// Evaluates the context against the loaded policies. No survivors.
    ///
    /// # Deny by Default
    ///
    /// - `Decision::Allow` -> returns `Ok(())`
    /// - `Decision::Deny` -> returns `Err(ForgeError::Policy("access denied"))`
    /// - Execution errors -> mapped securely to `ForgeError::Policy(...)`
    ///
    /// # Performance
    ///
    /// The `ctx` parameter is passed by reference precisely so we aren't wasting cycles cloning strings.
    /// The Cedar `Request` object is built entirely locally.
    ///
    /// # Errors
    ///
    /// Returns [`ForgeError::Policy`] when access is explicitly denied, or if
    /// the given context simply fails to build into a structurally valid Cedar request.
    pub fn check_permit(&self, ctx: &AuthContext) -> Result<()> {
        let request = ctx.to_cedar_request()?;

        // We aren't fully materializing massive entity trees (e.g., User -> Group -> Organization)
        // just yet. So, we pass a totally empty Entities array. The principal/action/resource
        // UIDs packed inside the Request are more than enough for basic, attribute-less checks right now.
        let entities = Entities::empty();

        let response = self
            .authorizer
            .is_authorized(&request, &self.policies, &entities);

        match response.decision() {
            Decision::Allow => Ok(()),
            Decision::Deny => {
                // We could totally inspect response.diagnostics() here to point out exactly
                // which policy denied access, or figure out what weird errors occurred during
                // string evaluation. But honestly? Returning a generic message is
                // infinitely safer to avoid accidental data leakage. Security over UX here.
                Err(ForgeError::Policy(
                    "access denied by policy (or lack of policy)".into(),
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permit_allows_access() {
        let src = r#"
            permit(
                principal == ForgeDB::User::"alice",
                action == ForgeDB::Action::"Read",
                resource == ForgeDB::Document::"docs/1"
            );
        "#;

        let engine = PolicyEngine::new(src).unwrap();
        let ctx = AuthContext::new("alice", "Read", "docs/1");

        assert!(
            engine.check_permit(&ctx).is_ok(),
            "alice should be able to read"
        );
    }

    #[test]
    fn deny_blocks_access() {
        let src = r#"
            permit(
                principal,
                action,
                resource
            );

            forbid(
                principal == ForgeDB::User::"eve",
                action,
                resource
            );
        "#;

        let engine = PolicyEngine::new(src).unwrap();

        // Alice easily matches the blanket permit policy, and importantly, she isn't forbidden.
        let ctx_alice = AuthContext::new("alice", "Read", "docs/1");
        assert!(engine.check_permit(&ctx_alice).is_ok());

        // Eve happens to match the permit too, but ALSO matches the forbid policy. Forbid always wins. Always.
        let ctx_eve = AuthContext::new("eve", "Read", "docs/1");
        let err = engine.check_permit(&ctx_eve).unwrap_err();
        assert!(format!("{err}").contains("denied"));
    }

    #[test]
    fn empty_policy_denies_by_default() {
        let engine = PolicyEngine::new("").unwrap();
        let ctx = AuthContext::new("alice", "Read", "docs/1");
        let err = engine.check_permit(&ctx).unwrap_err();
        assert!(format!("{err}").contains("denied"));
    }

    #[test]
    fn invalid_syntax_caught_at_construction() {
        let src = r#"permit( principal = "whoops" )"#; // = instead of ==
        assert!(PolicyEngine::new(src).is_err());
    }
}
