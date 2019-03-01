mod ports;

use serde::{Serialize, Deserialize};

pub use ports::{Port, PortState};



#[derive(Debug, Deserialize, Serialize)]
pub enum Data {
    Ports(Vec<Port>),
}
