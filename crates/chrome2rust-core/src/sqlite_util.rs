use crate::error::ChromeError;
use rusqlite::{Connection, OpenFlags};
use std::collections::HashSet;
use std::path::Path;
use tempfile::TempDir;

/// Holds a forensic read-only SQLite connection opened against a safe temporary snapshot
/// (including `-wal`, `-shm`, and `-journal` sidecars) so live browser locks never block reads
/// and original evidence is never modified.
pub struct ForensicSqlite {
    pub conn: Connection,
    _temp_dir: TempDir,
}

impl ForensicSqlite {
    pub fn open_snapshot(db_path: &Path) -> Result<Self, ChromeError> {
        if !db_path.is_file() {
            return Err(ChromeError::NotFound(db_path.display().to_string()));
        }
        let meta = std::fs::metadata(db_path).map_err(|e| ChromeError::Io {
            path: db_path.display().to_string(),
            source: e,
        })?;
        if meta.len() < 16 {
            return Err(ChromeError::InvalidFormat(format!(
                "SQLite file too small ({} bytes): {}",
                meta.len(),
                db_path.display()
            )));
        }

        let temp_dir = TempDir::new().map_err(|e| ChromeError::Io {
            path: db_path.display().to_string(),
            source: e,
        })?;

        let file_name = db_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "db.sqlite".to_string());
        let dest_db = temp_dir.path().join(&file_name);

        std::fs::copy(db_path, &dest_db).map_err(|e| ChromeError::Io {
            path: db_path.display().to_string(),
            source: e,
        })?;

        for suffix in ["-wal", "-shm", "-journal"] {
            let sidecar_src = std::path::PathBuf::from(format!("{}{}", db_path.display(), suffix));
            if sidecar_src.is_file() {
                let sidecar_dst = std::path::PathBuf::from(format!("{}{}", dest_db.display(), suffix));
                let _ = std::fs::copy(&sidecar_src, &sidecar_dst);
            }
        }

        // Open RW on the *temp copy* first ONLY if WAL/journal exists so SQLite recovers uncommitted WAL frames,
        // or open RO directly if no WAL/journal exists. Original files on disk are NEVER touched.
        let has_wal = Path::new(&format!("{}-wal", dest_db.display())).is_file();
        let flags = if has_wal {
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX
        } else {
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX
        };

        let conn = Connection::open_with_flags(&dest_db, flags).map_err(|e| ChromeError::Sqlite {
            path: db_path.display().to_string(),
            message: e.to_string(),
        })?;

        if has_wal {
            let _ = conn.query_row("PRAGMA wal_checkpoint(PASSIVE)", [], |_| Ok(()));
        }

        Ok(Self {
            conn,
            _temp_dir: temp_dir,
        })
    }

    pub fn list_tables(&self) -> HashSet<String> {
        let mut out = HashSet::new();
        if let Ok(mut stmt) = self.conn.prepare("SELECT name FROM sqlite_master WHERE type='table'")
            && let Ok(rows) = stmt.query_map([], |row| row.get::<_, String>(0))
        {
            for name in rows.flatten() {
                out.insert(name);
            }
        }
        out
    }

    pub fn table_columns(&self, table: &str) -> HashSet<String> {
        let mut out = HashSet::new();
        // Sanitize identifier to alphanumeric/underscore
        if !table.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return out;
        }
        let sql = format!("PRAGMA table_info({table})");
        if let Ok(mut stmt) = self.conn.prepare(&sql)
            && let Ok(rows) = stmt.query_map([], |row| row.get::<_, String>(1))
        {
            for col in rows.flatten() {
                out.insert(col);
            }
        }
        out
    }

    pub fn meta_value(&self, key: &str) -> Option<String> {
        self.conn
            .query_row("SELECT value FROM meta WHERE key = ?1", [key], |row| {
                row.get::<_, rusqlite::types::Value>(0)
            })
            .ok()
            .and_then(|v| match v {
                rusqlite::types::Value::Text(s) => Some(s),
                rusqlite::types::Value::Integer(i) => Some(i.to_string()),
                _ => None,
            })
    }
}
