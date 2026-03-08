//! Common types for cursor-based pagination.
//!
//! We use cursor-based pagination (keyset pagination) instead of offset/limit
//! because offset forces the storage engine to scan and discard rows, which scales
//! terribly for deep pages. Cursors leverage the B-tree directly.

use serde::{Deserialize, Serialize};

/// Pagination parameters typically passed via query string.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PaginationParams {
    /// The document ID to start _after_. If absent, starts from the beginning.
    pub cursor: Option<String>,
    /// Maximum number of items to return. Defaults to 50 if missing.
    pub limit: Option<u32>,
    /// Catch-all for extra query parameters (like `where[field]=value`).
    #[serde(flatten)]
    pub query_filters: std::collections::HashMap<String, String>,
}

impl Default for PaginationParams {
    fn default() -> Self {
        Self {
            cursor: None,
            limit: Some(50),
            query_filters: std::collections::HashMap::new(),
        }
    }
}

impl PaginationParams {
    /// Resolves the requested limit, enforcing bounds.
    ///
    /// The default is 50. The hard ceiling is 1000 to prevent runaway
    /// memory allocation and massive API payloads.
    #[must_use]
    pub fn resolved_limit(&self) -> usize {
        self.limit.unwrap_or(50).clamp(1, 1000) as usize
    }
}

/// A standard paginated response envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PaginatedResponse<T> {
    /// The actual items for this page.
    pub data: Vec<T>,
    /// The cursor to pass in the next request to get the next page.
    /// Will be `None` if `has_more` is false.
    pub next_cursor: Option<String>,
    /// Whether there are more items beyond this page.
    pub has_more: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limit_resolution_bounds() {
        let empty = PaginationParams::default();
        assert_eq!(empty.resolved_limit(), 50);

        let over = PaginationParams {
            cursor: None,
            limit: Some(5000),
            query_filters: std::collections::HashMap::new(),
        };
        assert_eq!(over.resolved_limit(), 1000);

        let under = PaginationParams {
            cursor: None,
            limit: Some(0),
            query_filters: std::collections::HashMap::new(),
        };
        assert_eq!(under.resolved_limit(), 1);

        let fine = PaginationParams {
            cursor: None,
            limit: Some(150),
            query_filters: std::collections::HashMap::new(),
        };
        assert_eq!(fine.resolved_limit(), 150);
    }
}
