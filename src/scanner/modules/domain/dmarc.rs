use crate::scanner::{
    module,
    findings,
    Scan,
    Target,
    TargetKind,
};
use std::process::{Command};

pub struct Dmarc{}

impl module::BaseModule for Dmarc {
    fn name(&self) -> String {
        return String::from("domain/dmarc");
    }

    fn description(&self) -> String {
        return String::from("check if DNS DMARC record is missing or insufficeient");
    }

    fn author(&self) -> String {
        return String::from("Sylvain Kerkour <sylvain@kerkour.com>")
    }

    fn version(&self) -> String {
        return String::from("0.1.0");
    }
}

// TODO: only if root domain
impl module::HostModule for Dmarc {
    fn run(&self, _: &Scan, target: &Target) -> (Option<findings::Data>, Vec<String>) {
        let mut errs = vec!();
        let mut ret = None;
        let mut txt_output = String::new();
        let mut is_dmarc_record_missing = true;

        match target.kind {
            TargetKind::Ip => { return (ret, errs); },
            _ => {}, // if domain, continue
        }

        // first retrieve TXT records
        let dmarc_domain = format!("_dmarc.{}", &target.host);
        match Command::new("dig")
            .arg("+short")
            .arg("TXT")
            .arg(&dmarc_domain)
            .output()
            {
            Ok(dig_output) => txt_output = String::from_utf8_lossy(&dig_output.stdout).to_string(),
            Err(err)  => errs.push(format!("executing dig: {}", err)),
        };

        let records: Vec<String> = txt_output.split('\n')
            .map(|record| record.trim().to_string())
            .filter(|record| record.is_empty())
            .collect();

        let resolves = if records.len() != 0 { true } else { false };

        // for each record, check if DMARC data is present
        for record in &records {
            if record.to_lowercase().contains("v=dmarc1") {
                is_dmarc_record_missing = false;
                break;
            }
        }

        if is_dmarc_record_missing {
            ret = Some(findings::Data::Dmarc(findings::Dmarc{
                domain: dmarc_domain,
                records,
                resolves,
            }));
        }

        return (ret, errs);
    }
}
