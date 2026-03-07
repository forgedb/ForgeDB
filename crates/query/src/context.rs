//! Request context for Cedar policy evaluation.
//!
//! Every single time a user hits the database to touch a document, we have to build a Cedar
//! `Request` and pass it to the engine. The `AuthContext` struct holds the raw strings —
//! usually yanked straight from PASETO tokens or the route itself — and handles the slightly
//! tedious, but necessary, conversion into typed Cedar `EntityUid` objects.
//!
//! We pass this thing by reference (`&AuthContext`) on the hot path. Why? To keep allocations
//! as low as Cedar's API physically allows. Allocating in the query path is just asking for a bad time.

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
    /// # Errors
    ///
    /// Returns [`ForgeError::Policy`] if the principal, action, or resource
    /// strings can't be wrangled into valid Cedar `EntityUid`s. For instance,
    /// if some client sends over malicious characters that Cedar outright rejects in entity IDs.
    pub fn to_cedar_request(&self) -> Result<Request> {
        let principal_eid = format!(r#"ForgeDB::User::"{}""#, self.principal);
        let action_eid = format!(r#"ForgeDB::Action::"{}""#, self.action);
        let resource_eid = format!(r#"ForgeDB::Document::"{}""#, self.resource);

        let p_uid: EntityUid = principal_eid
            .parse()
            .map_err(|e| ForgeError::Policy(format!("invalid principal UID: {e}")))?;
        let a_uid: EntityUid = action_eid
            .parse()
            .map_err(|e| ForgeError::Policy(format!("invalid action UID: {e}")))?;
        let r_uid: EntityUid = resource_eid
            .parse()
            .map_err(|e| ForgeError::Policy(format!("invalid resource UID: {e}")))?;

        // No extra context yet (like IP address, location, or time of day).
        // Honestly, we probably don't need it right now.
        let context = Context::empty();

        Request::new(
            p_uid,
            a_uid,
            r_uid,
            context,
            Some(&crate::schema::forge_schema()?),
        )
        .map_err(|e| ForgeError::Policy(format!("failed to construct request: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_builds_valid_request() {
        let ctx = AuthContext::new("alice", "Read", "invoices/123");
        let req = ctx.to_cedar_request().expect("should build valid request");

        assert_eq!(
            req.principal().unwrap().to_string(),
            r#"ForgeDB::User::"alice""#
        );
        assert_eq!(
            req.action().unwrap().to_string(),
            r#"ForgeDB::Action::"Read""#
        );
        assert_eq!(
            req.resource().unwrap().to_string(),
            r#"ForgeDB::Document::"invoices/123""#
        );
    }

    #[test]
    // Note: We don't really have a clean way to force EntityUid parse failures
    // easily without generating totally malicious garbage strings that break Cedar's
    // parser (which would just be testing Cedar itself), but we know it handles normal email strings fine.
    fn context_handles_complex_strings() {
        let ctx = AuthContext::new("user_name@domain.com", "Write", "a/b/c/d");
        let req = ctx.to_cedar_request().unwrap();
        assert!(req.principal().is_some());
    }
}
