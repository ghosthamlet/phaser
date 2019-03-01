use crate::scanner::{
    findings,
    Scan,
    Target,
};

// BaseModule must be implemented by all modules, whether it be HostModules or PortModule
pub trait BaseModule {
    fn name(&self) -> String;
    fn description(&self) -> String;
    fn author(&self) -> String;
    fn version(&self) -> String;
}

// HostModule must be implemented by all modules to be used by the phaser scan engine.
// They will be run at most once per host.
pub trait HostModule: BaseModule {
    fn run(&self, scan: &Scan, target: &Target) -> (Option<findings::Data>, Vec<String>);
}

// PortModule must be implemented by all modules to be used by the phaser scanner engine.
// They will be run at most once per port per host.
pub trait PortModule: BaseModule {
    fn run(&self, scan: &Scan, target: &Target) -> (Option<findings::Data>, Vec<String>);
}
