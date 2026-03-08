use forge_types::{ForgeError, Result};
use redbx::{Database, ReadableDatabase, TableDefinition};
use serde::{Deserialize, Serialize};

/// Internal table mapping collections to their indexed fields.
pub(crate) const INDEX_REGISTRY_TABLE: &str = "_forge_indexes";

/// Serialized list of indexed fields for a collection.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct IndexedFields {
    pub(crate) fields: Vec<String>,
}

/// Computes the internal table name for a given secondary index.
pub fn index_table_name(collection: &str, field: &str) -> String {
    format!("_idx_{}_{}", collection, field)
}

/// Formats an index key. To support non-unique indexes, we append the document ID
/// to the field value, separated by a null byte `\0`.
///
/// Format: `[value_bytes]\0[doc_id_bytes]`
pub fn format_index_key(value: &[u8], doc_id: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(value.len() + 1 + doc_id.len());
    key.extend_from_slice(value);
    key.push(0);
    key.extend_from_slice(doc_id.as_bytes());
    key
}

/// Registry of secondary indexes, managing metadata and lifecycle.
pub struct IndexRegistry<'a> {
    db: &'a Database,
}

impl<'a> IndexRegistry<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Retrieves all indexed fields for a given collection.
    pub fn list_indexes(&self, collection: &str) -> Result<Vec<String>> {
        let table_def = TableDefinition::<&str, &[u8]>::new(INDEX_REGISTRY_TABLE);
        let txn = self.db.begin_read().map_err(redbx::Error::from)?;

        let table = match txn.open_table(table_def) {
            Ok(t) => t,
            Err(redbx::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(ForgeError::Storage(e.into())),
        };

        match table.get(collection).map_err(redbx::Error::from)? {
            Some(bytes) => {
                let registry: IndexedFields = crate::deserialize_doc(bytes.value())?;
                Ok(registry.fields)
            }
            None => Ok(Vec::new()),
        }
    }

    /// Registers a new field to be indexed for a collection.
    /// Note: This only updates metadata. The caller is responsible for backfilling
    /// the index table via `engine::rebuild_index`.
    pub fn create_index(&self, collection: &str, field: &str) -> Result<()> {
        let mut fields = self.list_indexes(collection)?;
        if fields.iter().any(|f| f == field) {
            return Ok(()); // Already exists
        }

        fields.push(field.to_string());
        let registry = IndexedFields { fields };
        let bytes = crate::serialize_doc(&registry)?;

        let table_def = TableDefinition::<&str, &[u8]>::new(INDEX_REGISTRY_TABLE);
        let txn = self.db.begin_write().map_err(redbx::Error::from)?;

        {
            let mut table = txn.open_table(table_def).map_err(redbx::Error::from)?;
            table
                .insert(collection, bytes.as_slice())
                .map_err(redbx::Error::from)?;
        }

        txn.commit().map_err(redbx::Error::from)?;
        Ok(())
    }

    /// Removes an index from the registry. The caller must drop the actual index table.
    pub fn drop_index(&self, collection: &str, field: &str) -> Result<()> {
        let mut fields = self.list_indexes(collection)?;
        let initial_len = fields.len();
        fields.retain(|f| f != field);

        if fields.len() == initial_len {
            return Ok(()); // Did not exist
        }

        let bytes = crate::serialize_doc(&IndexedFields { fields })?;
        let table_def = TableDefinition::<&str, &[u8]>::new(INDEX_REGISTRY_TABLE);
        let txn = self.db.begin_write().map_err(redbx::Error::from)?;

        {
            let mut table = txn.open_table(table_def).map_err(redbx::Error::from)?;
            table
                .insert(collection, bytes.as_slice())
                .map_err(redbx::Error::from)?;
        }

        // Also instruct redbx to delete the backing index table if possible
        // (redbx doesn't currently easily drop tables dynamically without iterating and deleting)
        // We leave the orphaned table data around since it won't be queried, or the caller can manually empty it.

        txn.commit().map_err(redbx::Error::from)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_index_key_builds_correctly() {
        let val = b"hello";
        let doc_id = "doc-123";
        let key = format_index_key(val, doc_id);

        assert_eq!(&key[0..5], b"hello");
        assert_eq!(key[5], 0);
        assert_eq!(&key[6..], b"doc-123");
    }
}
