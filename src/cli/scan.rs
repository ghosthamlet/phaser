use clap::{ArgMatches};
use crate::scanner::Scan;

// TODO
pub fn run(matches: &ArgMatches) -> Result<(), String> {
    if let Some(targets) = matches.values_of("targets") {
        targets.for_each(|target| println!("{}", target));
    }
    // if let Some(matches) = matches.subcommand_matches("targets") {
    //     let files: Vec<_> = matches.values_of("targets").unwrap().collect();
    //     println!("{}", files[0]);
    //     println!("{}", files[1]);
    // }
    // let mut scan = Scan::new();
    // scan.run();
    Ok(())
}
