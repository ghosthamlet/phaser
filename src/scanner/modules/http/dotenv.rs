use crate::{
    scanner::{
        module,
        findings,
        ReportV1,
        Target,
        ModuleName,
    },
    error::PhaserError,
};


pub struct Dotenv{}

impl module::BaseModule for Dotenv {
    fn name(&self) -> ModuleName {
        return ModuleName::HttpDotenv;
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

// TODO: error handling not found
impl module::PortModule for Dotenv {
    fn run(&self, _: &ReportV1, target: &Target, port: &findings::Port) -> Result<findings::ModuleResult, PhaserError> {
        let protocol = if port.http {
            "http"
        } else if port.https {
            "https"
        } else {
            ""
        };

        if protocol == "" {
            return Ok(findings::ModuleResult::None);
        }

        let url = format!("{}://{}:{}/", &protocol, &target.host, &port.id);
        let body = reqwest::get(&url)?
            .text()?;

        if is_dotenv(&body) {
            return Ok(findings::ModuleResult::Url(findings::Url{
                url,
            }));
        }

        return Ok(findings::ModuleResult::None);
    }
}

fn is_dotenv(content: &str) -> bool {
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
        if content.contains(clue) { acc + 1 } else { acc }
    });

    return count >= 1;
}


#[cfg(test)]
mod tests {
    use crate::scanner::module::BaseModule;

    #[test]
    fn module_name() {
        let module = super::Dotenv{};
        assert_eq!("http/dotenv", module.name().to_string());
    }

    #[test]
    fn is_dotenv() {
        let body = "AWS_KEY=xsxsxsxs
        xsxs
        xs
        xsxs
        xs
        xs";
        let body2 = "lol lol lol ol ol< LO> OL  <tle>Index of kerkour.com</title> sdsds";
        let body3 = "";

        assert_eq!(true, super::is_dotenv(body));
        assert_eq!(false, super::is_dotenv(body2));
        assert_eq!(false, super::is_dotenv(body3));
    }
}
