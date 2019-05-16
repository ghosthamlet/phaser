use serde::{Serialize, Deserialize};


#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ApiResponse {
    pub error: Option<String>,
    pub data: Option<ReportJob>,
    // pub status: u32,
}


#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReportJob {
    pub id: uuid::Uuid,
    pub scan_id: uuid::Uuid,
    pub targets: Vec<String>,
    pub profile: String,
}

// // MessageOut is used to send and receive messages between services
// // phaser -> kernel
// #[derive(Clone, Debug, Deserialize, Serialize)]
// #[serde(tag = "type", content = "data")]
// pub enum Out {
//     #[serde(rename = "scan_completed")]
//     ScanCompleted(ScanCompleted),
// }

// #[derive(Clone, Debug, Deserialize, Serialize)]
// pub struct ScanStarted {
//     pub report_id: uuid::Uuid,
//     pub started_at: String,
// }

// #[derive(Clone, Debug, Deserialize, Serialize)]
// pub struct ScanCompleted {
//     pub report_id: String,
//     // pub sah512: S,
// }

// #[derive(Clone, Debug, Deserialize, Serialize)]
// pub struct File {
//     pub path: String,
//     pub md5: Option<String>,
//     pub sha1: Option<String>,
//     pub sha256: Option<String>,
//     pub sha512: Option<String>,
// }
