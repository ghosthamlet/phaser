use clap::{ArgMatches};
use crate::scanner::{Scan, Target, Config};
use std::process;
use std::str::FromStr;

// TODO
pub fn run(matches: &ArgMatches) -> Result<(), String> {
    if let Some(targets) = matches.values_of("targets") {
        let targets = targets.map(|target| {
            Target::from_str(target)
        })
        .collect();

        match targets {
            Ok(targets) => {
                let config = Config{
                    data_folder: "scans".to_owned(),
                    ..Default::default()
                };
                let mut scan = Scan::new(config, targets);
                scan.run();
            },
            Err(err) => {
                println!("{:?}", err);
                process::exit(1);
            }
        }
    }
    Ok(())
}
