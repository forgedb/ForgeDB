//! Request context for Cedar policy evaluation.
//!
//! Every database hit builds a Cedar `Request` from this struct — principal comes
//! from the PASETO sub claim, action from the HTTP verb, resource from the route.
//!
//! One design choice worth flagging: all resources are always typed `ForgeDB::Document`.
//! The entity ID carries the full `"collection"` or `"collection/id"` string for
//! fine-grained policy discrimination. We could map each collection to its own entity
//! type (which the dynamic schema hot-reload work sets up), but that's a v0.3 feature;
//! doing it at the context level caused a nasty class of bugs where `collection == "user"`
//! produced `ForgeDB::User::\"user\"` — a *principal* type, not a resource type — and
//! Cedar's strict request validation blew up before any policy ever ran.
//!
//! Kept by reference on the hot path to avoid gratuitous clones.

use cedar_policy::{Context, EntityUid, Request};

use forge_types::{ForgeError, Result};

/// The "who, what, and to-what" of an authorization check.
///
/// This is the exact piece of data we shove into the policy engine. It perfectly maps to the
/// `ForgeDB` namespace we defined over in `schema.rs`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthContext {
    /// The PASETO sub claim (e.g. "user-123")
    pub principal: String,
    /// The operation (must be "Read", "Write", "Delete")
    pub action: String,
    /// The collection + document ID (e.g. "users/user-123")
    pub resource: String,
}

/// Escapes a string for use as a Cedar entity ID within double quotes.
///
/// Prevents "Cedar injection" by ensuring that characters like double quotes
/// or backslashes can't be used to break out of the string literal and
/// inject additional policy logic.
fn cedar_escape(raw: &str) -> String {
    // Cedar uses standard C-style escaping for strings.
    raw.replace('\\', "\\\\").replace('"', "\\\"")
}

impl AuthContext {
    /// Creates a new AuthContext.
    pub fn new(
        principal: impl Into<String>,
        action: impl Into<String>,
        resource: impl Into<String>,
    ) -> Self {
        Self {
            principal: principal.into(),
            action: action.into(),
            resource: resource.into(),
        }
    }

    /// Converts this context into a strictly typed Cedar `Request`.
    ///
    /// Resources are always typed `ForgeDB::Document` regardless of the collection name.
    /// The full `"collection"` or `"collection/id"` string lives in the entity ID so Cedar
    /// policies can still discriminate at whatever granularity they want:
    ///
    /// ```cedar
    /// // Permit reads on the whole "posts" collection
    /// permit(principal, action == ForgeDB::Action::"Read",
    ///        resource == ForgeDB::Document::"posts");
    ///
    /// // Or a single document
    /// permit(principal, action == ForgeDB::Action::"Read",
    ///        resource == ForgeDB::Document::"posts/abc-123");
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`ForgeError::Policy`] if the action string is unrecognized or if Cedar
    /// rejects malformed characters in the principal/resource IDs after escaping.
    pub fn to_cedar_request(&self, schema: Option<&cedar_policy::Schema>) -> Result<Request> {
        let principal_eid = format!(r#"ForgeDB::User::"{}""#, cedar_escape(&self.principal));
        let action_eid = format!(r#"ForgeDB::Action::"{}""#, cedar_escape(&self.action));

        // Always Document — see module doc for why we stopped deriving from the collection name.
        let resource_eid = format!(r#"ForgeDB::Document::"{}""#, cedar_escape(&self.resource));

        let p_uid: EntityUid = principal_eid
            .parse()
            .map_err(|e| ForgeError::Policy(format!("invalid principal UID: {e}")))?;
        let a_uid: EntityUid = action_eid
            .parse()
            .map_err(|e| ForgeError::Policy(format!("invalid action UID: {e}")))?;
        let r_uid: EntityUid = resource_eid
            .parse()
            .map_err(|e| ForgeError::Policy(format!("invalid resource UID: {e}")))?;

        let context = Context::empty();

        Request::new(p_uid, a_uid, r_uid, context, schema)
            .map_err(|e| ForgeError::Policy(format!("failed to construct request: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_builds_valid_request() {
        let ctx = AuthContext::new("alice", "Read", "document/123");
        let req = ctx
            .to_cedar_request(None)
            .expect("should build valid request");

        assert_eq!(
            req.principal().unwrap().to_string(),
            r#"ForgeDB::User::"alice""#
        );
        assert_eq!(
            req.action().unwrap().to_string(),
            r#"ForgeDB::Action::"Read""#
        );
        // Resource is always ForgeDB::Document regardless of what the collection name is.
        assert_eq!(
            req.resource().unwrap().to_string(),
            r#"ForgeDB::Document::"document/123""#
        );
    }

    #[test]
    fn collection_named_user_resolves_as_document_not_principal_type() {
        let ctx = AuthContext::new("admin", "Read", "user");
        let req = ctx
            .to_cedar_request(None)
            .expect("collection named 'user' must not blow up Cedar request construction");

        assert_eq!(
            req.resource().unwrap().to_string(),
            r#"ForgeDB::Document::"user""#,
            "resource must always be Document, never a principal type"
        );
    }

    #[test]
    fn context_handles_complex_strings() {
        let ctx = AuthContext::new("user_name@domain.com", "Write", "a/b/c/d");
        let req = ctx.to_cedar_request(None).unwrap();
        assert!(req.principal().is_some());
    }

    #[test]
    fn cedar_injection_attempt_is_escaped() {
        // Attempting to inject a bypass: "principal,action,resource); //"
        let malicious = r#"alice", action, resource); //"#;
        let ctx = AuthContext::new(malicious, "Read", "document/1");
        let req = ctx
            .to_cedar_request(None)
            .expect("Escaping should make this a valid, if weird, ID");

        // The key check: Is the principal still exactly what we passed, but quoted?
        // Cedar .to_string() will show the escaped version.
        let p_str = req.principal().unwrap().to_string();
        assert!(p_str.contains(r#"alice\", action, resource); //"#));
        assert!(p_str.starts_with(r#"ForgeDB::User::"#));
    }
}
