use clap::{ArgMatches};
use crate::worker::{Worker};

pub fn run(_: &ArgMatches) -> Result<(), String> {
  Worker::new().run();
  Ok(())
}
