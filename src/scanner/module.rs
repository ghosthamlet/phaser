use crate::{
    scanner::{
        findings,
        Scan,
        Target,
        TargetError,
    },
    error::PhaserError,
};

// BaseModule must be implemented by all modules, whether it be HostModules or PortModule
pub trait BaseModule {
    fn name(&self) -> String;
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

// HostModule must be implemented by all modules to be used by the phaser scan engine.
// They will be run at most once per host.
pub trait HostModule: BaseModule {
    fn run(&self, scan: &Scan, target: &Target) -> Result<findings::Data, PhaserError>;
}

// PortModule must be implemented by all modules to be used by the phaser scanner engine.
// They will be run at most once per port per host.
pub trait PortModule: BaseModule {
    fn run(&self, scan: &Scan, target: &Target, port: &findings::Port) -> Result<findings::Data, PhaserError>;
}
