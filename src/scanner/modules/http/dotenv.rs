use crate::scanner::{
    module,
    findings,
    Scan,
    Target,
    TargetKind,
};
use std::process::{Command};
use regex::Regex;

pub struct Dotenv{}

impl module::BaseModule for Dotenv {
    fn name(&self) -> String {
        return "http/dotenv".to_string();
    }

    fn description(&self) -> String {
        return "Check for .env file disclosure".to_string();
    }

    fn author(&self) -> String {
        return "Sylvain Kerkour <sylvain@kerkour.com>".to_string();
    }

    fn version(&self) -> String {
        return "0.1.0".to_string();
    }
}

impl module::PortModule for Dotenv {
    fn run(&self, _: &Scan, target: &Target, port: &findings::Port) -> (Option<findings::Data>, Vec<String>) {
        let mut errs = vec!();
        let mut ret = None;

        let protocol = if port.http {
            "http"
        } else if port.https {
            "https"
        } else {
            ""
        };

        if protocol == "" {
            return (ret, errs);
        }

        let url = format!("{}://{}:{}/", &protocol, &target.host, &port.id);
        let body = reqwest::get(&url)
            .expect("error fetching url for dotenv")
            .text()
            .expect("error getting body to txt");

        let mut count = 0;
        let clues = vec!(
            "APP_ENV=",
            "DB_CONNECTION=",
            "DB_HOST=",
            "DB_PORT=",
            "DB_DATABASE=",
            "DB_USERNAME=",
            "DB_PASSWORD=",
            "REDIS_HOST=",
            "REDIS_PASSWORD=",
            "REDIS_PORT=",
            "AWS_KEY=",
            "AWS_SECRET=",
            "AWS_REGION=",
            "AWS_BUCKET=",
            "APP_NAME=",
            "AUTH_KEY=",
            "AUTH_SALT=",
            "LOGGED_IN_KEY=",
            "WP_ENV=",
            "S3_BUCKET=",
            "DATABASE_URL=",
            "REDIS_URL=",
            "EXPRESS_LOGGER=",
            "NEW_RELIC_LICENSE_KEY=",
        );

        let count = clues.iter().fold(0u32, |acc, clue| {
            if body.contains(clue) { acc + 1 } else { acc }
        });

        if count >= 1 {
            ret = Some(findings::Data::Url(findings::Url{
                url,
            }));
        }

        return (ret, errs);
    }
}
