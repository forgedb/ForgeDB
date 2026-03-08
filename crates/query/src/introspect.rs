//! Cedar namespace schema introspection.
//!
//! Exposes a structured representation of `schema.rs` so the Leptos dashboard
//! policy editor isn't flying blind. By hitting the introspection endpoint, the
//! frontend can power syntax highlighting, auto-complete, and basic static
//! analysis without needing to duplicate the schema structure in WASM.

use serde::Serialize;
use serde_json::Value;

use forge_types::Result;

use crate::schema::forge_schema_json;

/// The overall shape of the ForgeDB Cedar namespace.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct SchemaInfo {
    /// E.g., `User` or `Document`.
    pub entity_types: Vec<EntityTypeInfo>,
    /// Authorized verbs like `Read`, `Write`, `Delete`.
    pub actions: Vec<ActionInfo>,
}

/// Represents a single Cedar entity type (like `User`) and its expected shape.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct EntityTypeInfo {
    /// Bare name: "User" (not fully qualified `ForgeDB::User`).
    pub name: String,
    /// What fields you can expect to dot-access in policies (e.g. `principal.role`).
    pub attributes: Vec<AttributeInfo>,
}

/// A specific attribute on an entity type.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct AttributeInfo {
    pub name: String,
    pub type_name: String,
    pub required: bool,
}

/// An action dictating what principals can act upon what resources.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct ActionInfo {
    /// Bare name: "Read"
    pub name: String,
    /// E.g. ["User"]
    pub principal_types: Vec<String>,
    /// E.g. ["Document"]
    pub resource_types: Vec<String>,
}

/// Parses the active Cedar schema into a lightweight structured view.
///
/// # Panics
///
/// Expects the underlying JSON backing `forge_schema` to retain its
/// predictable shape. If someone radically changes how `schema.rs` is
/// constructed (e.g., dropping the `ForgeDB` namespace entirely), this
/// will error out safely rather than panicking.
///
/// # Errors
/// Returns [`ForgeError::Policy`] if the schema introspection fails.
pub fn introspect_schema() -> Result<SchemaInfo> {
    let schema_json = forge_schema_json();

    let ns = schema_json.get("ForgeDB").ok_or_else(|| {
        forge_types::ForgeError::Policy("ForgeDB namespace missing from schema".into())
    })?;

    let mut entity_types = Vec::new();
    if let Some(types) = ns.get("entityTypes").and_then(Value::as_object) {
        for (name, def) in types {
            let mut attributes = Vec::new();
            if let Some(attrs) = def
                .get("shape")
                .and_then(|s| s.get("attributes"))
                .and_then(Value::as_object)
            {
                for (attr_name, attr_def) in attrs {
                    let type_name = attr_def
                        .get("type")
                        .and_then(Value::as_str)
                        .unwrap_or("Unknown")
                        .to_string();
                    let required = attr_def
                        .get("required")
                        .and_then(Value::as_bool)
                        .unwrap_or(false);

                    attributes.push(AttributeInfo {
                        name: attr_name.clone(),
                        type_name,
                        required,
                    });
                }
            }
            entity_types.push(EntityTypeInfo {
                name: name.clone(),
                attributes,
            });
        }
    }
    // Ensures stable ordering for deterministic tests and frontend rendering
    entity_types.sort_by(|a, b| a.name.cmp(&b.name));

    let mut actions = Vec::new();
    if let Some(acts) = ns.get("actions").and_then(Value::as_object) {
        for (name, def) in acts {
            let applies_to = def.get("appliesTo");

            let principal_types = applies_to
                .and_then(|a| a.get("principalTypes"))
                .and_then(Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(Value::as_str)
                        .map(String::from)
                        .collect()
                })
                .unwrap_or_default();

            let resource_types = applies_to
                .and_then(|a| a.get("resourceTypes"))
                .and_then(Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(Value::as_str)
                        .map(String::from)
                        .collect()
                })
                .unwrap_or_default();

            actions.push(ActionInfo {
                name: name.clone(),
                principal_types,
                resource_types,
            });
        }
    }
    // Ensure stable ordering
    actions.sort_by(|a, b| a.name.cmp(&b.name));

    Ok(SchemaInfo {
        entity_types,
        actions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn introspection_yields_expected_shape() {
        let info = introspect_schema().expect("introspection must succeed");

        assert_eq!(info.entity_types.len(), 2, "Expected User and Document");

        let doc_type = info
            .entity_types
            .iter()
            .find(|e| e.name == "Document")
            .unwrap();
        assert_eq!(doc_type.attributes.len(), 1);
        assert_eq!(doc_type.attributes[0].name, "owner");
        assert_eq!(doc_type.attributes[0].type_name, "String");
        assert!(!doc_type.attributes[0].required);

        assert_eq!(info.actions.len(), 3, "Expected Read, Write, Delete");

        let read_action = info.actions.iter().find(|a| a.name == "Read").unwrap();
        assert_eq!(read_action.principal_types, vec!["User"]);
        assert_eq!(read_action.resource_types, vec!["Document"]);
    }
}
