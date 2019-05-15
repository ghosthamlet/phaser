use serde::{Deserialize, Serialize};
use std::env;


#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Config {
    pub environment: String,
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
            environment: get_env("RUST_ENV"),
            assets_folder: get_env("ASSETS_FOLDER"),
            sentry_url: get_env("SENTRY_URL"),
            api_url: get_env("API_URL"),
            phaser_secret: get_env("PHASER_SECRET"),
            data_folder: get_env("DATA_FOLDER"),
        };
    }
}
