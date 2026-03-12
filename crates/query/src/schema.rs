//! Cedar schema definitions for ForgeDB.
//!
//! Look, Cedar requires a schema to validate policies before they ever get evaluated.
//! By forcing all policies against this strict schema at engine startup, we catch
//! the stupid stuff — spelling mistakes, weird type errors (like checking if `principal.age > "bob"`),
//! and completely fabricated actions — immediately. I prefer this over letting bad logic crash queries in production, which usually bites later.
//!
//! We define three core entity types here:
//! - `ForgeDB::User`: The principal. The actual human (or service) doing the thing.
//! - `ForgeDB::Action`: The operation. We only trust Read, Write, and Delete right now.
//! - `ForgeDB::Document`: The resource. The literal data being touched. Might have an `owner` string attached to it.
//!
//! Constructed dynamically via Cedar's JSON format because parsing it isn't the bottleneck right now.

use cedar_policy::Schema;
use serde_json::json;

use forge_types::{ForgeError, Result};

/// Returns the raw JSON value that defines the ForgeDB Cedar schema.
///
/// We expose this separately from [`forge_schema`] because the `cedar_policy::Schema`
/// type is opaque and doesn't provide a stable way to round-trip back out to JSON.
/// The introspection API needs to read this raw structure.
#[must_use]
pub fn forge_schema_json() -> serde_json::Value {
    json!({
        "ForgeDB": {
            "entityTypes": {
                "User": {
                    "shape": {
                        "type": "Record",
                        "attributes": {
                            "role": { "type": "String", "required": false }
                        }
                    }
                },
                "Document": {
                    "shape": {
                        "type": "Record",
                        "attributes": {
                            "owner": { "type": "String", "required": false }
                        }
                    }
                }
            },
            "actions": {
                "Read": {
                    "appliesTo": {
                        "principalTypes": ["User"],
                        "resourceTypes": ["Document"]
                    }
                },
                "Write": {
                    "appliesTo": {
                        "principalTypes": ["User"],
                        "resourceTypes": ["Document"]
                    }
                },
                "Delete": {
                    "appliesTo": {
                        "principalTypes": ["User"],
                        "resourceTypes": ["Document"]
                    }
                }
            }
        }
    })
}

/// Spits out a compiled Cedar schema for ForgeDB from a parsed JSON value.
///
/// This dictates exactly what entity types, actions, and context shapes are actually legal
/// in the system. Any user policy that tries to invent an action (e.g., `permit(principal, action == Action::"Hack", resource)`)
/// gets decisively rejected by the engine *before* we even attempt to evaluate it. Fail fast, always.
///
/// # Errors
///
/// Returns [`ForgeError::Policy`] if the provided JSON schema is invalid.
pub fn parse_schema(json_val: serde_json::Value) -> Result<Schema> {
    Schema::from_json_value(json_val)
        .map_err(|e| ForgeError::Policy(format!("failed to parse Cedar schema: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_compiles_successfully() {
        let schema =
            parse_schema(forge_schema_json()).expect("hardcoded schema must be entirely valid");

        let ns = schema
            .action_entities()
            .expect("should have at least some actions defined");
        assert!(
            !ns.is_empty(),
            "schema actions shouldn't be empty, obviously"
        );
    }
}
