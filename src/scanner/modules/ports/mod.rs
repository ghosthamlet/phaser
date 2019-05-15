mod nmap;

use crate::{
    scanner::{
        module,
        findings,
        ReportV1,
        Target,
    },
    error::PhaserError,
};
use std::process::{Command};
use serde_xml_rs::from_reader;
use nmap::{Run, Port, PortStatus};
use reqwest;
use std::time::Duration;


pub struct Ports{}

impl module::BaseModule for Ports {
    fn name(&self) -> String {
        return "ports".to_string();
    }

    fn description(&self) -> String {
        return "Scan ports".to_string();
    }

    fn author(&self) -> String {
        return "Sylvain Kerkour <sylvain@kerkour.com>".to_string();
    }

    fn version(&self) -> String {
        return "0.1.0".to_string();
    }
}

impl module::HostModule for Ports {
    fn run(&self, _: &ReportV1, target: &Target) -> Result<findings::Data, PhaserError> {
        let ports = [
            1,
            3,
            4,
            6,
            7,
            9,
            13,
            21,        // ftp
            22,        // telnet
            25,        // smtp
            80,        // http
            81,        // Goahead
            88, 10088, // zendserver
            443,                    // https
            902,                    // vsphere
            1080,                   // socks
            2003, 2004, 2023, 2024, // carbon
            2368,       // ghost
            2375,       // swarm
            2424, 2480, // orientDB
            2379, 2380, // etcd
            3000, 3001, 3002, 3003, // grafana, aerospike
            3306,       // mysql
            3389,       // rdp
            4000,       // TiDB
            4200,       // crateDB
            4444, 7899, // notary
            5000,                   // logstash
            5080, 6080, 9080, 7080, // dgraph
            5900, 5901, // vnc
            5984, 5986, 4369, //couchdb
            5432,                                                             // postgreSql
            5601,                                                             // kibana
            6362, 6363, 6364, 6365, 6366, 6367, 6368, 6369, 6370, 6371, 6372, // neo4j
            7474, 7473, 7687, 5000, 6000, 7000, 5001, 6001, 2003, 3637, 1337, // neo4j
            8001, 8444, // kong
            7199, 7000, 7001, 9160, 9042, 61621, //cassandra
            8080,                    // http
            8081, 7077, 4040, 18080, // spark
            8086, 8088, 8083, 2003, // influxdb
            8091, 8092, 8093, 8094, 11210, // couchbase
            8101, 8102, 22122, 22222, // dynomite
            8125, 8126, // statsd
            8300,       // consul
            8443,       // https
            8529, 8530, //arangoDB
            9042,                   // scylladb
            9092, 2181, 2888, 3888, // kafka
            9200, 9300, //elasticsearch
            11211,        // memcached
            26257,        // cockroachDB
            27017, 27018, // mongodb
            28015, 29015, // rethinkdb
            50000,                                           // jenkins
            50070, 50470, 50075, 50090, 50105, 50030, 50060, // hadoop
            5672, 5671, 15672, 4369, 25672, // rabbitmq
            1521, 1630, 3938, 1158, 5520, 5540, 5560, 5580, 5600, 5620, 5640, 5660, // oracledb
            61000, 11000, 49896, 49895, 49897, //oracledb
        ];

        // converts ports to Vec<String> and then join with "," to be consumed by nmap
        let ports = ports.iter().map(|port| port.to_string()).collect::<Vec<String>>().join(",");

        let nmap_output = Command::new("nmap")
            .arg("-p")
            .arg(ports)
            .arg("-oX")
            .arg("-")
            .arg(&target.host)
            .arg("-dd")
            .arg("--host-timeout")
            .arg("2m")
            .output()?;
        let output = String::from_utf8_lossy(&nmap_output.stdout).to_string();


        if !output.is_empty() {
            let run = from_reader::<_, Run>(output.as_bytes())?;
            let mut ports = vec!();
            if run.hosts.len() == 1 {
                let nmap_ports = run.hosts[0].ports.ports.iter()
                    .filter(|port| port.state.state == PortStatus::Open).collect::<Vec<&Port>>();
                for nmap_port in &nmap_ports {
                    let (http, https) = check_http_s(target, nmap_port.id);
                    ports.push(findings::Port{
                        id: nmap_port.id,
                        state: findings::PortState::Open,
                        http,
                        https,
                    });
                }
                return Ok(findings::Data::Ports(ports));
            } else {
                return Err(PhaserError::Nmap(format!("wrong number of nmap hosts: expected 1, got: {}", run.hosts.len())));
            }

        }

        return Ok(findings::Data::None);
    }
}

// TODO log error + user agent
fn check_http_s(target: &Target, port: u16) -> (bool, bool) {
    let mut is_http = false;
    let mut is_https = false;

    let client = match reqwest::Client::builder()
        .gzip(true)
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::RedirectPolicy::none())
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build() {
        Ok(cl) => cl,
        Err(_) => return (is_http, is_https),
    };

   if let Ok(_) = client.get(&format!("https://{}:{}", target.host, port)).send() {
        is_https = true;
   }
   if let Ok(_) = client.get(&format!("http://{}:{}", target.host, port)).send() {
       is_http = true;
   }

    return (is_http, is_https);
}



#[cfg(test)]
mod tests {
    use crate::scanner::module::BaseModule;

    #[test]
    fn module_name() {
        let module = super::Ports{};
        assert_eq!("ports", module.name());
    }
}
