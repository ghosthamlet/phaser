use config::Config;
use crate::log::macros::*;
use rusoto_core::credential::{EnvironmentProvider};
use rusoto_s3::{S3Client, PutObjectRequest,S3};
use rusoto_core::request::HttpClient;
use rusoto_core::Region;
use std::str::FromStr;
use crate::worker::{config, messages};
use crate::scanner;
use std::path::{Path};
use reqwest::header;
use std::{thread, time};
use std::fs;
use std::io::Read;

pub struct Worker {
    config: config::Config,
    api_client: reqwest::Client,
    s3_client: S3Client,
}

impl Worker {
     pub fn new() -> Worker {
        let config = Config::new();

        let mut headers = header::HeaderMap::new();
        let auth_header = format!("Secret {}", &config.phaser_secret);
        headers.insert(header::AUTHORIZATION, header::HeaderValue::from_str(&auth_header).unwrap());

        let s3_client = S3Client::new_with(
            HttpClient::new().expect("failed to create request dispatcher"),
            EnvironmentProvider::default(),
            Region::from_str(&config.aws_region).unwrap(),
        );

        let api_client = reqwest::Client::builder()
            .gzip(true)
            .timeout(time::Duration::from_secs(30))
            .default_headers(headers)
            .build().expect("error building api client");
        return Worker{
            config,
            api_client,
            s3_client,
        };
     }

    pub fn run(&self) {
        let endpoint = format!("{}/phaser/job", self.config.api_url);

        loop {
            info!("fetching job {}", &endpoint);
            let mut res = self.api_client.get(&endpoint).send().expect("sending request from worker");
            let res: messages::ApiResponse = res.json().expect("parsing api response to JSON");
            if res.status == 200 {
                match res.data {
                    Some(messages::ApiData::ScanQueued(ref payload)) => {
                        info!("job received report: {}", &payload.report_id);
                        let targets = payload.targets.iter().map(|target| scanner::Target::from_str(target).unwrap()).collect();
                        let data_folder = Path::new(&self.config.data_folder).join(&payload.report_id).to_str().expect("error creating data folder").to_string();
                        let config = scanner::Config{
                            scan_id: payload.scan_id.clone(),
                            report_id: payload.report_id.clone(),
                            data_folder,
                            assets_folder: self.config.assets_folder.clone(),
                        };
                        let mut scan = scanner::Scan::new(config, targets);
                        scan.run();

                        let mut f = fs::File::open(&format!("{}/{}/scan.json", &self.config.data_folder, &payload.report_id)).unwrap();
                        let mut contents: Vec<u8> = Vec::new();
                        match f.read_to_end(&mut contents) {
                            Err(why) => panic!("Error opening file to send to S3: {}", why),
                            Ok(_) => {
                                let req = PutObjectRequest {
                                    bucket: self.config.aws_s3_bucket.clone(),
                                    key: format!("phaser/scans/{}/reports/{}/scan.json", payload.scan_id.clone(), payload.report_id.clone()),
                                    body: Some(contents.into()),
                                    ..Default::default()
                                };
                                self.s3_client.put_object(req).sync().expect("Couldn't PUT object");
                                let endpoint = format!("{}/phaser/reports/{}", self.config.api_url, &payload.report_id);

                                self.api_client.put(&endpoint)
                                    // .json(&messages::ScanCompleted{report_id: payload.report_id.clone()})
                                    .send().expect("sending scan_completed request from worker");
                            }
                        }
                    },
                    _ => {},
                }
            } else {
                info!("no jobs, witing 15 secs");
                thread::sleep(time::Duration::from_secs(15))
            }
        }
    }
}
