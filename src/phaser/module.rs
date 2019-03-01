use serde::{Deserialize, Serialize};

// type BaseModule interface {
// 	Name() string
// 	Description() string
// 	Author() string
// 	Version() string
// }

#[derive(Debug, Deserialize, Serialize)]
pub enum FindingData {
    Lol,
}

// BaseModule must be implemented by all modules, whether it be HostModules or PortModule
pub trait BaseModule {
    fn name() -> String;
    fn description() -> String;
    fn author() -> String;
    fn version() -> String;
}

// HostModule must be implemented by all modules to be used by the phaser scan engine.
// They will be run at most once per host.
pub trait HostModule: BaseModule {
    fn run(&self) -> (FindingData, Vec<String>);
}

// PortModule must be implemented by all modules to be used by the phaser scanner engine.
// They will be run at most once per port per host.
pub trait PortModule: BaseModule {
    fn run(&self) -> (FindingData, Vec<String>);
}
