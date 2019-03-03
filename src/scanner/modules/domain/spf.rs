use crate::scanner::{
    module,
    findings,
    Scan,
    Target,
    TargetKind,
};
use std::process::{Command};

pub struct Spf{}

impl module::BaseModule for Spf {
    fn name(&self) -> String {
        return String::from("domain/spf");
    }

    fn description(&self) -> String {
        return String::from("check if DNS SPF record is missing or insufficeient");
    }

    fn author(&self) -> String {
        return String::from("Sylvain Kerkour <sylvain@kerkour.com>")
    }

    fn version(&self) -> String {
        return String::from("0.1.0");
    }
}

// TODO: only if root domain
impl module::HostModule for Spf {
    fn run(&self, _: &Scan, target: &Target) -> (Option<findings::Data>, Vec<String>) {
        let mut errs = vec!();
        let mut ret = None;
        let mut txt_output = String::new();
        let mut is_spf_record_missing = true;

        if let TargetKind::Ip = target.kind {
            return (ret, errs);
        };

        // first retrieve TXT records
        match Command::new("dig")
            .arg("+short")
            .arg("TXT")
            .arg(&target.host)
            .output()
            {
            Ok(dig_output) => txt_output = String::from_utf8_lossy(&dig_output.stdout).to_string(),
            Err(err)  => errs.push(format!("executing dig: {}", err)),
        };

        let records: Vec<String> = txt_output.split('\n')
            .map(|record| record.trim().to_string())
            .filter(|record| !record.is_empty())
            .collect();

        let resolves = if records.len() != 0 { true } else { false };

        // for each record, check if DMARC data is present
        for record in &records {
            if record.to_lowercase().contains("v=spf1") {
                is_spf_record_missing = false;
                break;
            }
        }

        if is_spf_record_missing {
            ret = Some(findings::Data::Spf(findings::domain::Spf{
                domain: target.host.clone(),
                records,
                resolves,
            }));
        }

        return (ret, errs);
    }
}
