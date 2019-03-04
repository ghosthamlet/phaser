// use std::str::FromStr;
// use trust_dns::client::{Client, SyncClient};
// use trust_dns::udp::UdpClientConnection;
// use trust_dns::op::DnsResponse;
// use trust_dns::rr::{DNSClass, Name, RData, Record, RecordType};
// use std::net::{SocketAddr, IpAddr, Ipv4Addr};
use crate::scanner::{
    module,
    findings,
    Scan,
    Target,
    TargetKind,
};
use std::process::{Command};

pub struct Cname{}

impl module::BaseModule for Cname {
    fn name(&self) -> String {
        return String::from("domain/cname");
    }

    fn description(&self) -> String {
        return String::from("retrieve CNAME record data");
    }

    fn author(&self) -> String {
        return String::from("Sylvain Kerkour <sylvain@kerkour.com>")
    }

    fn version(&self) -> String {
        return String::from("0.1.0");
    }
}

// TODO: remove unwraps
impl module::HostModule for Cname {
    fn run(&self, _: &Scan, target: &Target) -> (Option<findings::Data>, Vec<String>) {
        let mut errs = vec!();
        let mut output = String::new();
        let mut ret = None;

        if let TargetKind::Ip = target.kind {
            return (ret, errs);
        };

        match Command::new("dig")
            .arg("+short")
            .arg("CNAME")
            .arg(&target.host)
            .output()
            {
            Ok(dig_output) => output = String::from_utf8_lossy(&dig_output.stdout).to_string(),
            Err(err)  => errs.push(format!("executing dig: {}", err)),
        };

        output = output.trim().to_string();
        if !output.is_empty() {
            ret = Some(findings::Data::Domain(output));
        }

        return (ret, errs);
        // let mut errs = vec!();
        // let mut ret = None;
        // // Google dns server, 8.8.8.8:53
        // let dns_server_address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53);

        // match target.kind {
        //     TargetKind::Ip => { return (ret, errs); },
        //     _ => {}, // if domain, continue
        // }

        // let conn = UdpClientConnection::new(dns_server_address).unwrap();
        // let client = SyncClient::new(conn);

        // // Specify the name, note the final '.' which specifies it's an FQDN
        // let name = Name::from_str(&target.host).unwrap();

        // // NOTE: see 'Setup a connection' example above
        // // Send the query and get a message response, see RecordType for all supported options
        // let response: DnsResponse = client.query(&name, DNSClass::IN, RecordType::CNAME).unwrap();

        // // Messages are the packets sent between client and server in DNS, DnsResonse's can be
        // //  dereferenced to a Message. There are many fields to a Message, It's beyond the scope
        // //  of these examples to explain them. See trust_dns::op::message::Message for more details.
        // //  generally we will be interested in the Message::answers
        // let answers: &[Record] = response.answers();

        // // Records are generic objects which can contain any data.
        // //  In order to access it we need to first check what type of record it is
        // //  In this case we are interested in A, IPv4 address
        // if answers.len() > 0 {
        //     if let &RData::CNAME(ref name) = answers[0].rdata() {
        //         ret = Some(findings::Data::Domain(name.to_utf8()));
        //     }
        //     // TODO: else, log weird data
        // }
    }
}


#[cfg(test)]
mod tests {
    use crate::scanner::module::BaseModule;

    #[test]
    fn module_name() {
        let module = super::Cname{};
        assert_eq!("domain/cname", module.name());
    }
}
