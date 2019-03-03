use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Dmarc {
    pub domain: String,
    pub records: Vec<String>,
    pub resolves: bool,
}
