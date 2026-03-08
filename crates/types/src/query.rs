use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Maximum allowed depth for relational joins to prevent combinatorial explosions
/// and ensure predictable < 1ms response times.
pub const MAX_JOIN_DEPTH: usize = 2;

/// A graph node representing a relational join to another collection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinNode {
    /// The target collection to join with.
    pub collection: String,
    /// The local field on the parent document. (e.g., `author_id`)
    pub on: String,
    /// The remote field on the target document. Typically `id`.
    /// Due to our strict "fast path" architecture, joining on fields other
    /// than `id` requires a secondary index on the target collection.
    pub target: String,
    /// Nested child joins. For example, joining `comments` onto `posts`,
    /// then joining `author` onto each `comment`.
    #[serde(default)]
    pub joins: HashMap<String, JoinNode>,
}

impl JoinNode {
    /// Validates that the recursive join structure does not exceed `MAX_JOIN_DEPTH`.
    pub fn validate_depth(&self, current_depth: usize) -> Result<(), &'static str> {
        if current_depth > MAX_JOIN_DEPTH {
            return Err("Join depth exceeds the maximum allowed limit of 2");
        }
        for child in self.joins.values() {
            child.validate_depth(current_depth + 1)?;
        }
        Ok(())
    }
}

/// The root payload for the `POST /v1/_query` endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinQuery {
    /// The root collection to scan.
    pub collection: String,
    /// Exact match filters applied to the root collection to limit the working set.
    #[serde(default, rename = "where")]
    pub filter: HashMap<String, serde_json::Value>,
    /// The relational tree of joins.
    #[serde(default, rename = "join")]
    pub joins: HashMap<String, JoinNode>,
    /// The maximum number of root documents to return. Default 50.
    pub limit: Option<u32>,
    /// Keyset cursor for pagination over the root collection.
    pub cursor: Option<String>,
}

impl JoinQuery {
    /// Validates the query for safety limits, checking max depth.
    pub fn validate(&self) -> Result<(), &'static str> {
        for node in self.joins.values() {
            node.validate_depth(1)?;
        }
        Ok(())
    }

    /// Resolves the requested root limits securely.
    pub fn resolved_limit(&self) -> usize {
        self.limit.unwrap_or(50).clamp(1, 1000) as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_join_depth_allowed() {
        let mut child_join = HashMap::new();
        child_join.insert(
            "author".into(),
            JoinNode {
                collection: "users".into(),
                on: "author_id".into(),
                target: "id".into(),
                joins: HashMap::new(),
            },
        );

        let mut root_joins = HashMap::new();
        root_joins.insert(
            "comments".into(),
            JoinNode {
                collection: "comments".into(),
                on: "id".into(),
                target: "post_id".into(),
                joins: child_join,
            },
        );

        let query = JoinQuery {
            collection: "posts".into(),
            filter: HashMap::new(),
            joins: root_joins,
            limit: None,
            cursor: None,
        };

        assert!(query.validate().is_ok());
    }

    #[test]
    fn excessive_join_depth_rejected() {
        let deep_node = JoinNode {
            collection: "level3".into(),
            on: "x".into(),
            target: "id".into(),
            joins: HashMap::new(),
        };

        let mut mid_map = HashMap::new();
        mid_map.insert("l3".into(), deep_node);

        let mid_node = JoinNode {
            collection: "level2".into(),
            on: "x".into(),
            target: "id".into(),
            joins: mid_map,
        };

        let mut top_map = HashMap::new();
        top_map.insert("l2".into(), mid_node);

        let top_node = JoinNode {
            collection: "level1".into(),
            on: "x".into(),
            target: "id".into(),
            joins: top_map,
        };

        let mut root_joins = HashMap::new();
        root_joins.insert("l1".into(), top_node);

        let query = JoinQuery {
            collection: "root".into(),
            filter: HashMap::new(),
            joins: root_joins,
            limit: None,
            cursor: None,
        };

        assert!(query.validate().is_err());
    }
}
