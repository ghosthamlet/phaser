mod config;

use crate::log::macros::*;
use std::{thread, time};

pub struct Worker {
    config: config::Config,
}

impl Worker {
     pub fn new() -> Worker {
         return Worker{ config: config::Config::new() };
     }

    pub fn run(&self) {
        info!("worker started");
        loop {
            thread::sleep(time::Duration::from_secs(1));
            info!("worker waiting");
        }
    }
}
