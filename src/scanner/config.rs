use serde::{Serialize, Deserialize};

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Config {
    pub id: Option<String>,
    pub report_id: Option<String>,
    pub data_folder: String,
    pub assets_folder: String,
}
