mod log;
mod cli;
mod worker;

use clap::{App, ArgMatches, SubCommand, AppSettings};
// use slog_scope;
use std::process;
use serde::{Deserialize, Serialize};
// use crate::log::macros::*;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct User {
    name: String,
    age: u8,
}

fn main() {
    let matches = App::new(clap::crate_name!())
        .author(clap::crate_authors!())
        .version(clap::crate_version!())
        .about(clap::crate_description!())
        .setting(AppSettings::ArgRequiredElseHelp) // display help when no subcommand provided
        .subcommand(SubCommand::with_name("worker")
            .about("Run the scanner as a worker. Wait for messages from remote sources. Configuration is done with environment variable")
        )
        .get_matches();

     let (_guard, _log) = log::setup_slog();

    if let Err(e) = run(&matches) {
        println!("Application error: {}", e);
        process::exit(1);
    }
}

fn run(matches: &ArgMatches) -> Result<(), String> {
    match matches.subcommand() {
        ("worker", Some(m)) => cli::worker::run(m),
         _ => Ok(()),
    }
}
