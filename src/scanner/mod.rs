mod scan;
mod module;
mod target;
mod profile;

pub mod modules;
pub mod findings;
pub use module::{BaseModule, HostModule, PortModule};
pub use scan::{Scan, Config};
pub use target::{Target, IpVersion, TargetError, TargetKind};
pub use profile::Profile;
use rusoto_s3::{S3Client};

pub struct Scanner {
    pub s3_client: Option<S3Client>,
}
