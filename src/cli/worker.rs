use clap::{ArgMatches};
use crate::worker::{Worker};
use sentry;
use dotenv::dotenv;
use std::env;
use std::{thread, time};
use std::sync::mpsc;


// we start sentry here, because tracking stop when guard go out of scope, so it can't be in Worker::new
pub fn run(_: &ArgMatches) -> Result<(), String> {
    env::set_var("RUST_BACKTRACE", "1");
    dotenv().expect("failed to read .env file");
    let _sentry = sentry::init(env::var("SENTRY_URL").unwrap());
    sentry::integrations::panic::register_panic_handler();


    let (tx, rx) = mpsc::channel();
    let n = 21;
    for i in 0..n {
        let tx1 = mpsc::Sender::clone(&tx);
        thread::spawn(move || {
            Worker::new(i).run();
            tx1.send(i).unwrap();
        });
        thread::sleep(time::Duration::from_secs(1))
    }

    for received in rx {
        println!("worker: {} terminated", received);
    }
    Ok(())
}
