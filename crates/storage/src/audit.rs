//! Immutable audit logging.
//!
//! Handles append-only operations to the `_audit` table. We enforce immutability
//! at the storage engine level by explicitly rejecting inserts if the key already exists.
//! No silent overwrites. No exceptions.

use redbx::{Database, ReadableDatabase, ReadableTable, TableDefinition};

use forge_types::{AuditEntry, ForgeError, Result};

const AUDIT_TABLE: TableDefinition<[u8; 16], &[u8]> = TableDefinition::new("_audit");

/// A wrapper around a redbx Database specifically for appending to the audit log.
pub struct AuditLog<'a> {
    db: &'a Database,
}

impl<'a> AuditLog<'a> {
    /// Constructs a new AuditLog interface for the given database.
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Appends a new audit entry to the log.
    ///
    /// # Immutability Guarantee
    /// This method explicitly checks for UUID collisions. If an entry with the
    /// same ID somehow already exists, it violently rejects the write with a
    /// [`ForgeError::Audit`] rather than silently overwriting it.
    ///
    /// # Errors
    /// Returns an error if serialization fails, the table can't be opened,
    /// or if a collision is detected.
    pub fn append(&self, entry: &AuditEntry) -> Result<()> {
        let write_tx = self
            .db
            .begin_write()
            .map_err(|e| ForgeError::Storage(e.into()))?;

        {
            let mut table = write_tx
                .open_table(AUDIT_TABLE)
                .map_err(|e| ForgeError::Storage(e.into()))?;

            let key = entry.id.into_bytes();

            // The ironclad rule of the audit log: Append only. Zero overwrites.
            if table
                .get(&key)
                .map_err(|e| ForgeError::Storage(e.into()))?
                .is_some()
            {
                return Err(ForgeError::Audit(
                    "audit log collision detected: immutable violation".into(),
                ));
            }

            let value = rmp_serde::to_vec(entry).map_err(|e| {
                ForgeError::Serialization(format!("failed to serialize audit entry: {e}"))
            })?;

            table
                .insert(&key, value.as_slice())
                .map_err(|e| ForgeError::Storage(e.into()))?;
        }

        write_tx
            .commit()
            .map_err(|e| ForgeError::Storage(e.into()))?;
        Ok(())
    }

    /// Iterates through all entries in the audit log.
    /// Useful for the dashboard or security tooling.
    pub fn iter(&self) -> Result<Vec<AuditEntry>> {
        let read_tx = self
            .db
            .begin_read()
            .map_err(|e| ForgeError::Storage(e.into()))?;

        let table = match read_tx.open_table(AUDIT_TABLE) {
            Ok(t) => t,
            Err(redbx::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(ForgeError::Storage(e.into())),
        };

        let mut entries = Vec::new();
        let iter = table.iter().map_err(|e| ForgeError::Storage(e.into()))?;

        for item in iter {
            let (_, value) = item.map_err(|e| ForgeError::Storage(e.into()))?;
            let entry: AuditEntry = rmp_serde::from_slice(value.value()).map_err(|e| {
                ForgeError::Serialization(format!("failed to deserialize audit entry: {e}"))
            })?;
            entries.push(entry);
        }

        Ok(entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use forge_types::Outcome;
    use tempfile::NamedTempFile;

    fn setup_db() -> (Database, NamedTempFile) {
        let tempfile = NamedTempFile::new().unwrap();
        // Database requires a password string for encryption
        let db = Database::create(tempfile.path(), "test-password-123").unwrap();

        // Initialize the table so iter() doesn't fail on empty
        let write_tx = db.begin_write().unwrap();
        let _ = write_tx.open_table(AUDIT_TABLE).unwrap();
        write_tx.commit().unwrap();

        (db, tempfile)
    }

    #[test]
    fn write_and_read_back() {
        let (db, _file) = setup_db();
        let log = AuditLog::new(&db);

        let entry1 = AuditEntry::new("alice", "Read", "docs", None, Outcome::Permit);
        let entry2 = AuditEntry::new("eve", "Delete", "users", Some("u1".into()), Outcome::Deny);

        log.append(&entry1).expect("should append successfully");
        log.append(&entry2).expect("should append successfully");

        let entries = log.iter().expect("should iterate successfully");
        assert_eq!(entries.len(), 2);

        // Redb guarantees sorted keys (UUID bytes), so order isn't guaranteed
        // insertion order, but we can verify both exist.
        let ids: Vec<_> = entries.iter().map(|e| e.id).collect();
        assert!(ids.contains(&entry1.id));
        assert!(ids.contains(&entry2.id));
    }

    #[test]
    fn collision_rejected() {
        let (db, _file) = setup_db();
        let log = AuditLog::new(&db);

        let entry = AuditEntry::new("alice", "Read", "docs", None, Outcome::Permit);

        log.append(&entry).expect("first append should work");

        // Exact same entry (same UUID) -> should fail violently.
        let err = log.append(&entry).unwrap_err();
        assert!(format!("{err}").contains("immutable violation"));
    }

    #[test]
    fn entries_survive_reopen() {
        let tempfile = NamedTempFile::new().unwrap();
        let path = tempfile.path().to_owned();

        let entry = AuditEntry::new("alice", "Read", "docs", None, Outcome::Permit);

        {
            let db = Database::create(&path, "test-password-123").unwrap();
            let write_tx = db.begin_write().unwrap();
            let _ = write_tx.open_table(AUDIT_TABLE).unwrap();
            write_tx.commit().unwrap();

            let log = AuditLog::new(&db);
            log.append(&entry).unwrap();
        }

        // Reopen database
        let db = Database::create(&path, "test-password-123").unwrap();
        let log = AuditLog::new(&db);
        let entries = log.iter().unwrap();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, entry.id);
    }
}
