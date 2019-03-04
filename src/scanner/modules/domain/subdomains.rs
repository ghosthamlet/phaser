use crate::scanner::{
    module,
    findings,
    Scan,
    Target,
    TargetKind,
};
use postgres::{Connection, TlsMode};

pub struct Subdomains{}

impl module::BaseModule for Subdomains {
    fn name(&self) -> String {
        return String::from("domain/subdomains");
    }

    fn description(&self) -> String {
        return String::from("Find subdomains for a given domain");
    }

    fn author(&self) -> String {
        return String::from("Sylvain Kerkour <sylvain@kerkour.com>")
    }

    fn version(&self) -> String {
        return String::from("0.1.0");
    }
}

impl module::HostModule for Subdomains {
    fn run(&self, _: &Scan, target: &Target) -> (Option<findings::Data>, Vec<String>) {
        let errs = vec!();
        let mut ret = None;
        let mut domains = vec!();

        if let TargetKind::Ip = target.kind {
            return (ret, errs);
        };

        let conn = Connection::connect("postgres://guest@crt.sh:5432/certwatch", TlsMode::None).unwrap();

        let subdomains_pattern = format!("%.{}", &target.host);

        let index = match subdomains_pattern.find('%') {
            Some(i) => i,
            None => 0,
        };
        let index_reverse = match subdomains_pattern.chars().rev().collect::<String>().find('%') {
            Some(i) => i,
            None => 0,
        };

        let query = if index < index_reverse {
            "SELECT DISTINCT ci.NAME_VALUE as domain
			FROM certificate_identity ci
			WHERE reverse(lower(ci.NAME_VALUE)) LIKE reverse(lower($1))"
        } else {
             "SELECT DISTINCT ci.NAME_VALUE as domain
            FROM certificate_identity ci
            WHERE lower(ci.NAME_VALUE) LIKE lower($1)"
        };

        let rows = conn.query(query, &[&subdomains_pattern]).unwrap();
        for row in &rows {
            domains.push(row.get(0));
        }
        ret = Some(findings::Data::Domains(domains));

        return (ret, errs);
    }
}
