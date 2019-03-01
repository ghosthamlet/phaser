use clap::{ArgMatches};
use crate::scanner::scan::Scan;

// TODO
pub fn run(_matches: &ArgMatches) -> Result<(), String> {
    let mut scan = Scan::new();
    scan.run();
    Ok(())
}
