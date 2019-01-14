mod info;
mod commands;
mod worker;
mod scanner;


use clap::{Arg, ArgMatches, App, SubCommand, AppSettings};
use std::process;
use env_logger;
use dotenv;
use sentry;
use std::env;


fn main() {
    dotenv::dotenv().expect("Failed to read .env file");
    env_logger::init();
    match env::var("SENTRY_URL") {
        Ok(v) => {
            let _guard = sentry::init(v);
            sentry::integrations::panic::register_panic_handler();
        }
        Err(_) => {},
    }


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

    if let Err(e) = run(&matches) {
        println!("Application error: {}", e);
        process::exit(1);
    }
}

fn run(matches: &ArgMatches) -> Result<(), String> {
    match matches.subcommand() {
        ("scan", Some(m)) => commands::scan::run(m),
        ("worker", Some(m)) => commands::worker::run(m),
        ("version", Some(m)) => commands::version::run(m),
         _ => Ok(()),
    }
}
