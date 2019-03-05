use serde::{Serialize, Deserialize};

// Message is used to send and receive messages between services
// kernel -> phaser
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", content = "data")]
pub enum In {
    #[serde(rename = "scan_queued")]
    ScanQueued{ scan_id: String, targets: Vec<String>, profile: String, report_id: String },
}

// MessageOut is used to send and receive messages between services
// phaser -> kernel
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", content = "data")]
pub enum Out {
    #[serde(rename = "scan_started")]
    ScanStarted{ report_id: String, started_at: String },
    #[serde(rename = "scan_completed")]
    ScanCompleted{ report_id: String, file: File },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct File {
    pub path: String,
    pub md5: Option<String>,
    pub sha1: Option<String>,
    pub sha256: Option<String>,
    pub sha512: Option<String>,
}
