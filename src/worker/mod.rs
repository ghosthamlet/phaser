mod config;
pub mod messages;


use log::{info, error};
use rusoto_sqs::{SqsClient, ReceiveMessageRequest, Sqs, DeleteMessageRequest, Message};
use rusoto_core::credential::{EnvironmentProvider};
use rusoto_core::request::HttpClient;
use rusoto_core::Region;
use std::env;
use serde_json;
use std::str::FromStr;


pub struct Worker{
    config: config::Config,
    client: SqsClient,
}

fn get_env(var: &str) -> String {
    match env::var(var) {
        Ok(v) => v,
        Err(_err) => panic!("Missing ENV variable: {}", var),
    }
}

impl Worker {
    pub fn new() -> Worker {
        let config = config::Config{
            environment: get_env("ENVIRONMENT"),
            aws_secret_access_key: get_env("AWS_SECRET_ACCESS_KEY"),
            aws_access_key_id: get_env("AWS_ACCESS_KEY_ID"),
            aws_region: get_env("AWS_REGION"),
            aws_sqs_queue_api_to_phaser: get_env("AWS_SQS_QUEUE_API_TO_PHASER"),
            aws_sqs_queue_phaser_to_api: get_env("AWS_SQS_QUEUE_PHASER_TO_API"),
            aws_s3_bucket: get_env("AWS_S3_BUCKET"),
            assets_path: get_env("ASSETS_PATH"),
        };

        let client = SqsClient::new_with(
            HttpClient::new().expect("failed to create request dispatcher"),
            EnvironmentProvider::default(),
            Region::from_str(&config.aws_region).unwrap(),
        );

        Worker{config, client}
    }

    pub fn run(&self) -> Option<String> {
        info!("listenning queue for async messages: {}", self.config.aws_sqs_queue_api_to_phaser);

        loop {
            let mut req = ReceiveMessageRequest::default();
            req.queue_url = self.config.aws_sqs_queue_api_to_phaser.clone();
            req.max_number_of_messages = Some(1);
            match self.client.receive_message(req).sync() {
                Ok(received) => {
                    match received.messages {
                        Some(messages) => {
                            info!("{} sqs messages received", messages.len());
                            messages.iter()
                            .for_each(|message| self.process_queue_message(message.clone()));
                        },
                        _ => info!("0 sqs messages received"),
                    }
                },
                Err(err) => error!("error receiving sqs message: {:?}", err),
            }
        }
    }

    fn process_queue_message(&self, message: Message) {

        let m: messages::AsyncIn = serde_json::from_str(&message.body.unwrap()).unwrap();
        info!("message received: {:?}", m);
        let delete_req = DeleteMessageRequest{
            queue_url: self.config.aws_sqs_queue_api_to_phaser.clone(),
            receipt_handle: message.receipt_handle.unwrap(),
        };
        match self.client.delete_message(delete_req).sync() {
            Ok(_) => println!("sqs message successfully deleted"),
            Err(err) => error!("error deleting sqs message: {:?}", err),
        }
    }
}
