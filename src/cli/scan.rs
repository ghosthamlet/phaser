use clap::{ArgMatches};
use crate::phaser::scan::Scan;

// TODO
pub fn run(_matches: &ArgMatches) -> Result<(), String> {
    let scan = Scan::new();
    scan.run();
    Ok(())
}
