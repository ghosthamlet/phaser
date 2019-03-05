use serde::{Serialize, Deserialize};

// Message is used to send and receive messages between services
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", content = "data")]
pub enum Message {
    // kernel -> phaser
    #[serde(rename = "scan_queued")]
    ScanQueued{ scan_id: String, targets: Vec<String>, profile: String, report_id: String },
    // phaser -> kernel
    ScanStarted{ report_id: String, started_at: String },
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
