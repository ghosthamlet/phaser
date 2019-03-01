mod config;

use config::Config;
use crate::log::macros::*;
use std::{thread, time};
use rusoto_sqs::{SqsClient};
use rusoto_core::credential::{EnvironmentProvider};
use rusoto_core::request::HttpClient;
use rusoto_core::Region;
use std::str::FromStr;

pub struct Worker {
    config: config::Config,
    sqs_client: SqsClient,
}

impl Worker {
     pub fn new() -> Worker {
         let config = Config::new();

        let sqs_client = SqsClient::new_with(
            HttpClient::new().expect("failed to create request dispatcher"),
            EnvironmentProvider::default(),
            Region::from_str(&config.aws_region).unwrap(),
        );
        return Worker{
            config,
            sqs_client,
        };
     }

    pub fn run(&self) {
        info!("worker started");
        loop {
            thread::sleep(time::Duration::from_secs(1));
            info!("worker waiting");
        }
    }
}
