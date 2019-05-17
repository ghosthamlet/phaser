use serde::{Serialize, Deserialize};
use crate::{
    scanner::{
        findings,
        ReportV1,
        Target,
        TargetError,
    },
    error::PhaserError,
};

// BaseModule must be implemented by all modules, whether it be HostModules or PortModule
pub trait BaseModule {
    fn name(&self) -> ModuleName;
    fn description(&self) -> String;
    fn author(&self) -> String;
    fn version(&self) -> String;

    fn err(&self, err: &PhaserError) -> TargetError {
        return TargetError{
            module: findings::Module{
                name: self.name(),
                version: self.version(),
            },
            error: err.to_string(),
        };
    }

    fn findings(&self, data: findings::Data) -> findings::Finding {
        return findings::Finding{
            module: findings::Module{
                name: self.name(),
                version: self.version(),
            },
            data,
        };
    }
}

// HostModule must be implemented by all modules to be used by the phaser report engine.
// They will be run at most once per host.
pub trait HostModule: BaseModule {
    fn run(&self, report: &ReportV1, target: &Target) -> Result<findings::Data, PhaserError>;
}

// PortModule must be implemented by all modules to be used by the phaser scanner engine.
// They will be run at most once per port per host.
pub trait PortModule: BaseModule {
    fn run(&self, report: &ReportV1, target: &Target, port: &findings::Port) -> Result<findings::Data, PhaserError>;
}


#[derive(Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum ModuleName {
    #[serde(rename = "http/directory-listing")]
    HttpDirectoryListing,
    #[serde(rename = "http/ds-store")]
    HttpDsStore,
    #[serde(rename = "http/dotenv")]
    HttpDotenv,
}

impl std::fmt::Display for ModuleName {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", serde_json::to_string(self).expect("error serializing ModuleName"))
    }
}
