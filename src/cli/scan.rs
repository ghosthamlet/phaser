use clap::{ArgMatches};
use crate::scanner::{Scan, Target, Config};
use std::process;
use std::str::FromStr;
use uuid::Uuid;
use std::path::{Path};

// TODO
pub fn run(matches: &ArgMatches) -> Result<(), String> {
    if let Some(targets) = matches.values_of("targets") {
        let targets = targets.map(|target| {
            Target::from_str(target)
        })
        .collect();

        match targets {
            Ok(targets) => {
                let uuid = Uuid::new_v4().to_hyphenated().to_string();
                let data_folder = Path::new("reports").join(&uuid).to_str().expect("error creating data folder").to_string();
                let config = Config{
                    report_id: uuid.clone(),
                    scan_id: uuid,
                    data_folder,
                    assets_folder: "assets".to_string(),
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
