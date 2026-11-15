use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ChromeError {
    #[error("I/O error at {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("Path does not exist: {0}")]
    NotFound(String),

    #[error("Invalid cache or artifact format: {0}")]
    InvalidFormat(String),

    #[error("SQLite error on {path}: {message}")]
    Sqlite { path: String, message: String },

    #[error("Decompression failed ({encoding}): {message}")]
    Decompress { encoding: String, message: String },

    #[error("Decryption failed: {0}")]
    Decrypt(String),

    #[error("Export error: {0}")]
    Export(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WarningSeverity {
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticWarning {
    pub severity: WarningSeverity,
    pub component: String,
    pub artifact_path: String,
    pub message: String,
}

impl DiagnosticWarning {
    pub fn info(component: impl Into<String>, path: impl AsRef<std::path::Path>, message: impl Into<String>) -> Self {
        Self {
            severity: WarningSeverity::Info,
            component: component.into(),
            artifact_path: path.as_ref().display().to_string(),
            message: message.into(),
        }
    }

    pub fn warn(component: impl Into<String>, path: impl AsRef<std::path::Path>, message: impl Into<String>) -> Self {
        Self {
            severity: WarningSeverity::Warn,
            component: component.into(),
            artifact_path: path.as_ref().display().to_string(),
            message: message.into(),
        }
    }

    pub fn error(component: impl Into<String>, path: impl AsRef<std::path::Path>, message: impl Into<String>) -> Self {
        Self {
            severity: WarningSeverity::Error,
            component: component.into(),
            artifact_path: path.as_ref().display().to_string(),
            message: message.into(),
        }
    }
}
