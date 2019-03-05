use serde::{Deserialize, Serialize};
use std::env;


#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Config {
    pub environment: String,
    pub aws_access_key_id: String,
    pub aws_secret_access_key: String,
    pub aws_region: String,
    pub aws_s3_bucket: String,
    pub assets_folder: String,
    pub sentry_url: String,
    pub api_url: String,
    pub phaser_secret: String,
    pub data_folder: String,
}

fn get_env(var: &str) -> String {
    match env::var(var) {
        Ok(v) => v,
        Err(_err) => panic!("missing ENV var: {}", var),
    }
}

impl Config {
    pub fn new() -> Config {
        return Config{
            environment: get_env("ENVIRONMENT"),
            aws_access_key_id: get_env("AWS_ACCESS_KEY_ID"),
            aws_secret_access_key: get_env("AWS_SECRET_ACCESS_KEY"),
            aws_region: get_env("AWS_REGION"),
            aws_s3_bucket: get_env("AWS_S3_BUCKET"),
            assets_folder: get_env("ASSETS_FOLDER"),
            sentry_url: get_env("SENTRY_URL"),
            api_url: get_env("API_URL"),
            phaser_secret: get_env("PHASER_SECRET"),
            data_folder: get_env("DATA_FOLDER"),
        };
    }
}
