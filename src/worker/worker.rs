use config::Config;
use crate::log::macros::*;
use rusoto_sqs::{SqsClient, ReceiveMessageRequest, Sqs, Message, DeleteMessageRequest};
use rusoto_core::credential::{EnvironmentProvider};
use rusoto_core::request::HttpClient;
use rusoto_core::Region;
use std::str::FromStr;
use crate::worker::{config, messages};
use crate::scanner;
use std::path::{Path};

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
        info!("listenning queue for async messages: {}", self.config.aws_sqs_queue_api_to_phaser);

        loop {
            let mut req = ReceiveMessageRequest::default();
            req.queue_url = self.config.aws_sqs_queue_api_to_phaser.clone();
            req.max_number_of_messages = Some(1);
            match self.sqs_client.receive_message(req).sync() {
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
        let m: messages::In = serde_json::from_str(&message.body.unwrap()).unwrap();
        info!("message received: {:?}", m);
        // run scan
        match m {
            messages::In::ScanQueued(ref request) => {
                let targets = request.targets.iter().map(|target| scanner::Target::from_str(target).unwrap()).collect();
                let data_folder = Path::new("scans").join(&request.scan_id).to_str().expect("error creating data folder").to_string();
                let config = scanner::Config{
                    scan_id: request.scan_id.clone(),
                    data_folder,
                    assets_folder: "assets".to_string(),
                    ..Default::default()
                };
                let mut scan = scanner::Scan::new(config, targets);
                scan.run();
            }
        }


        let delete_req = DeleteMessageRequest{
            queue_url: self.config.aws_sqs_queue_api_to_phaser.clone(),
            receipt_handle: message.receipt_handle.unwrap(),
        };
        match self.sqs_client.delete_message(delete_req).sync() {
            Ok(_) => info!("sqs message successfully deleted"),
            Err(err) => error!("error deleting sqs message: {:?}", err),
        }
    }

}
