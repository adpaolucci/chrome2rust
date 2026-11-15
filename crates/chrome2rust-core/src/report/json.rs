use crate::error::ChromeError;
use crate::forensics::UserDataReport;

pub fn render_json_report(report: &UserDataReport) -> Result<String, ChromeError> {
    serde_json::to_string_pretty(report).map_err(|e| ChromeError::Export(e.to_string()))
}
