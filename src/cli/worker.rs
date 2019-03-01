use clap::{ArgMatches};
use crate::worker::{Worker};
use sentry;
use dotenv::dotenv;
use std::env;

// we start sentry here, because tracking stop when guard go out of scope, so it can't be in Worker::new
pub fn run(_: &ArgMatches) -> Result<(), String> {
    env::set_var("RUST_BACKTRACE", "1");
    dotenv().expect("failed to read .env file");
    let _sentry = sentry::init(env::var("SENTRY_URL").unwrap());
    sentry::integrations::panic::register_panic_handler();

    Worker::new().run();
    Ok(())
}
