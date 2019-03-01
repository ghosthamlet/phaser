use dotenv::dotenv;
use serde::{Deserialize, Serialize};
use sentry;
use std::env;


#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Config {
    pub environment: String,
    pub aws_access_key_id: String,
    pub aws_secret_access_key: String,
    pub aws_region: String,
    pub aws_sqs_queue_api_to_phaser: String,
    pub aws_sqs_queue_phaser_to_api: String,
    pub aws_s3_bucket: String,
    pub assets_folder: String,
    pub sentry_url: String,
}

fn get_env(var: &str) -> String {
    match env::var(var) {
        Ok(v) => v,
        Err(_err) => panic!("missing ENV var: {}", var),
    }
}

impl Config {
    pub fn new() -> Config {
        env::set_var("RUST_BACKTRACE", "1");
        dotenv().expect("failed to read .env file");
        let _guard = sentry::init(get_env("SENTRY_URL"));
        sentry::integrations::panic::register_panic_handler();
        return Config{
            environment: get_env("ENVIRONMENT"),
            aws_access_key_id: get_env("AWS_ACCESS_KEY_ID"),
            aws_secret_access_key: get_env("AWS_SECRET_ACCESS_KEY"),
            aws_region: get_env("AWS_REGION"),
            aws_sqs_queue_api_to_phaser: get_env("AWS_SQS_QUEUE_API_TO_PHASER"),
            aws_sqs_queue_phaser_to_api: get_env("AWS_SQS_QUEUE_PHASER_TO_API"),
            aws_s3_bucket: get_env("AWS_S3_BUCKET"),
            assets_folder: get_env("ASSETS_FOLDER"),
            sentry_url: get_env("SENTRY_URL"),
        };
    }
}
