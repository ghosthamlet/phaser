use serde_derive::{Serialize, Deserialize};
use chrono::prelude::{DateTime, Utc};
use std::fmt;

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PayloadIn {
    ScanQueued(ScanQueued),
}

impl fmt::Display for PayloadIn {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match *self {
            PayloadIn::ScanQueued(_) => "scan_queued",
        };
        write!(f, "{}", s)?;
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PayloadOut {
    ScanCompleted(ScanCompleted),
    ScanStarted(ScanStarted),
}

impl fmt::Display for PayloadOut {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match *self {
            PayloadOut::ScanCompleted(_) => "scan_completed",
            PayloadOut::ScanStarted(_) => "scan_started",
        };
        write!(f, "{}", s)?;
        Ok(())
    }
}


#[derive(Debug, Serialize, Deserialize)]
pub struct AsyncIn {
    pub r#type: String,
    pub data: PayloadIn,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AsyncOut {
    pub r#type: String,
    pub data: PayloadOut,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanQueued {
    pub scan_id: String,
    pub targets: Vec<String>,
    pub profile: String,
    pub report_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanCompleted {
    pub report_id: String,
    pub file: File,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct File {
    pub path: String,
    pub sha512: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanStarted {
    pub report_id: String,
    pub started_at: DateTime<Utc>,
}
