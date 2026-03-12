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
    /// # Errors
    ///
    /// Returns [`ForgeError::Policy`] if the principal, action, or resource
    /// strings can't be wrangled into valid Cedar `EntityUid`s. For instance,
    /// if some client sends over malicious characters that Cedar outright rejects in entity IDs.
    pub fn to_cedar_request(&self, schema: Option<&cedar_policy::Schema>) -> Result<Request> {
        let parts: Vec<&str> = self.resource.splitn(2, '/').collect();
        let entity_type = if parts.len() == 2 {
            // "users/123" -> entity_type = "users", entity_id = "123"
            parts[0]
        } else {
            // "users" -> entity_type = "users", entity_id = "*"
            parts[0]
        };
        let entity_type_cap = match entity_type {
            "_" => "Document".to_string(), // fallback
            other => {
                // Capitalize first letter to match Cedar conventions usually
                let mut c = other.chars();
                match c.next() {
                    None => String::new(),
                    Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
                }
            }
        };

        let principal_eid = format!(r#"ForgeDB::User::"{}""#, cedar_escape(&self.principal));
        let action_eid = format!(r#"ForgeDB::Action::"{}""#, cedar_escape(&self.action));
        let resource_eid = format!(
            r#"ForgeDB::{}::"{}""#,
            entity_type_cap,
            cedar_escape(&self.resource)
        );

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
        assert_eq!(
            req.resource().unwrap().to_string(),
            r#"ForgeDB::Document::"document/123""#
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
