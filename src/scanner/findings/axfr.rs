use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Axfr {
    pub server: String,
    pub response: String,
}
