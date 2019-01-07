use chrono::prelude::{DateTime, Utc};
use serde_derive::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct Scan {
    pub id: String,
    pub started_at: DateTime<Utc>,
    pub duration: u64,
    pub phaser_version: String,
}


impl Scan {
    fn run(&self) {
        crate::scanner::checks::ports::run(self.clone());
    }
}
