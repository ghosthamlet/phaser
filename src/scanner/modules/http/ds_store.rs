use crate::{
    scanner::{
        module,
        findings,
        Scan,
        Target,
    },
    error::PhaserError,
};


pub struct DsStore{}

impl module::BaseModule for DsStore {
    fn name(&self) -> String {
        return "http/ds-store".to_string();
    }

    fn description(&self) -> String {
        return "Check for .DS_Store file disclosure".to_string();
    }

    fn author(&self) -> String {
        return "Sylvain Kerkour <sylvain@kerkour.com>".to_string();
    }

    fn version(&self) -> String {
        return "0.1.0".to_string();
    }
}

// TODO: handle error
impl module::PortModule for DsStore {
    fn run(&self, _: &Scan, target: &Target, port: &findings::Port) -> Result<findings::Data, PhaserError> {
        let protocol = if port.http {
            "http"
        } else if port.https {
            "https"
        } else {
            ""
        };

        if protocol == "" {
            return Ok(findings::Data::None);
        }

        let url = format!("{}://{}:{}/.DS_Store", &protocol, &target.host, &port.id);
        let mut body = reqwest::get(&url)?;

        let mut buf: Vec<u8> = vec!();
        body.copy_to(&mut buf)?;


        if is_ds_store(&buf) {
            return Ok(findings::Data::Url(findings::Url{
                url,
            }));
        }

        return Ok(findings::Data::None);
    }
}

fn is_ds_store(content: &[u8]) -> bool {
    if content.len() < 8 {
        return false;
    }

    let signature = [0x0, 0x0, 0x0, 0x1, 0x42, 0x75, 0x64, 0x31];

    return &content[0..8] == &signature;
}


#[cfg(test)]
mod tests {
    use crate::scanner::module::BaseModule;

    #[test]
    fn module_name() {
        let module = super::DsStore{};
        assert_eq!("http/ds-store", module.name());
    }

    #[test]
    fn is_dotenv() {
        let body = "Aswswswsw";
        let body2 = [0x00, 0x00, 0x00, 0x01, 0x42, 0x75, 0x64, 0x31, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x08, 0x0];

        assert_eq!(false, super::is_ds_store(body.as_bytes()));
        assert_eq!(true, super::is_ds_store(&body2));
    }

}
