//! Immutable audit log entry definitions.
//!
//! Because real security isn't just about stopping bad things; it's about
//! unequivocally proving who did them when the inevitable incident response happens.
//! These entries are designed to be completely immutable. Once written, they stay.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The verdict of a policy evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Outcome {
    /// The action was explicitly allowed by a `permit` policy.
    Permit,
    /// The action was blocked by a `forbid` policy or caught by the deny-by-default net.
    Deny,
}

/// A single, append-only record of an authorization event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Globally unique, cryptographically random ID for this specific audit record.
    pub id: Uuid,
    /// Timestamp in milliseconds since UNIX epoch.
    pub ts: u64,
    /// The principal (user/service) attempting the action.
    pub principal: String,
    /// The action attempted (e.g., "Read", "Write", "Delete").
    pub action: String,
    /// The collection being accessed (typically corresponds to the table).
    pub collection: String,
    /// The specific document ID targeted, if applicable.
    pub doc_id: Option<String>,
    /// The final, unapologetic result of the policy engine evaluation.
    pub outcome: Outcome,
}

impl AuditEntry {
    /// Constructs a completely fresh audit entry.
    ///
    /// The `id` is instantly generated as a v4 UUID, and the timestamp
    /// is captured right off the system clock. We don't let callers pass these in
    /// because we don't trust them to get it right.
    #[must_use]
    pub fn new(
        principal: impl Into<String>,
        action: impl Into<String>,
        collection: impl Into<String>,
        doc_id: Option<String>,
        outcome: Outcome,
    ) -> Self {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        Self {
            id: Uuid::new_v4(),
            ts,
            principal: principal.into(),
            action: action.into(),
            collection: collection.into(),
            doc_id,
            outcome,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_entry_generates_valid_defaults() {
        let entry = AuditEntry::new(
            "alice",
            "Read",
            "invoices",
            Some("123".into()),
            Outcome::Deny,
        );

        assert!(!entry.id.is_nil(), "uuid must be actually generated");
        assert!(entry.ts > 0, "timestamp must be captured");
        assert_eq!(entry.principal, "alice");
        assert_eq!(entry.outcome, Outcome::Deny);
    }
}
