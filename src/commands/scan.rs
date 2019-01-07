use clap::{ArgMatches};

pub fn run(_matches: &ArgMatches) -> Result<(), String> {
    println!("scan");
    Ok(())
}
