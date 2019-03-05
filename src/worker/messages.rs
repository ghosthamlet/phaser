use serde::{Serialize, Deserialize};

// Message is used to send and receive messages between services
// kernel -> phaser
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", content = "data")]
pub enum In {
    #[serde(rename = "scan_queued")]
    ScanQueued(ScanQueued),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ScanQueued {
    pub scan_id: String,
    pub targets: Vec<String>,
    pub profile: String,
    pub report_id: String
}

// MessageOut is used to send and receive messages between services
// phaser -> kernel
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", content = "data")]
pub enum Out {
    #[serde(rename = "scan_started")]
    ScanStarted(ScanStarted),
    #[serde(rename = "scan_completed")]
    ScanCompleted(ScanCompleted),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ScanStarted {
    pub report_id: String,
    pub started_at: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ScanCompleted {
    pub report_id: String,
    pub file: File,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct File {
    pub path: String,
    pub md5: Option<String>,
    pub sha1: Option<String>,
    pub sha256: Option<String>,
    pub sha512: Option<String>,
}
