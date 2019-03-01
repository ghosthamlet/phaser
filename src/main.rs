mod log;
mod cli;
mod worker;
mod info;
mod phaser;

use clap::{App, Arg, ArgMatches, SubCommand, AppSettings};
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
    let matches = App::new(info::NAME)
        .author(info::AUTHOR)
        .version(info::VERSION)
        .about(info::DESCRPITION)
        .setting(AppSettings::ArgRequiredElseHelp) // display help when no subcommand provided
        .subcommand(SubCommand::with_name("scan")
            .about("Run the scanner from CLI. Configuration is done with flags")
        )
        .subcommand(SubCommand::with_name("worker")
            .about("Run the scanner as a worker. Wait for messages from remote sources. Configuration is done with environment variable")
        )
        .subcommand(SubCommand::with_name("version")
            .about("Display the version and build information")
            .arg(Arg::with_name("format")
                .short("f")
                .default_value("text")
                .value_name("FORMAT")
                .help("The ouput format. Valid values are [text, json]")
            )
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
        ("version", Some(m)) => cli::version::run(m),
        ("scan", Some(m)) => cli::scan::run(m),
         _ => Ok(()),
    }
}
