use serde::{Serialize, Deserialize};
use crate::{
    scanner::{
        findings,
        ReportV1,
        Target,
    },
    error::PhaserError,
};


// BaseModule must be implemented by all modules, whether it be HostModules or PortModule
pub trait BaseModule {
    fn name(&self) -> ModuleName;
    fn description(&self) -> String;
    fn author(&self) -> String;
    fn version(&self) -> String;

    fn finding(&self, data: findings::Data) -> findings::Finding {
        return findings::Finding{
            module_version: self.version(),
            data,
        };
    }
}

// HostModule must be implemented by all modules to be used by the phaser report engine.
// They will be run at most once per host.
pub trait HostModule: BaseModule {
    fn run(&self, report: &ReportV1, target: &Target) -> Result<findings::Data, PhaserError>;
}

// PortModule must be implemented by all modules to be used by the phaser scanner engine.
// They will be run at most once per port per host.
pub trait PortModule: BaseModule {
    fn run(&self, report: &ReportV1, target: &Target, port: &findings::Port) -> Result<findings::Data, PhaserError>;
}


#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum ModuleName {
    #[serde(rename = "http/directory-listing")]
    HttpDirectoryListing,
    #[serde(rename = "http/ds-store")]
    HttpDsStore,
    #[serde(rename = "http/dotenv")]
    HttpDotenv,
    #[serde(rename = "ssltls/robot")]
    SsltlsRobot,
    #[serde(rename = "ssltls/cve-2014-0224")]
    SsltlsCve20140224,
    #[serde(rename = "ssltls/cve-2014-0160")]
    SsltlsCve20140160,
    #[serde(rename = "postgresql/unauthenticated-access")]
    PostgresqlUnauthenticatedAccess,
    #[serde(rename = "ports")]
    Ports,
    #[serde(rename = "mysql/unauthenticated-access")]
    MysqlUnauthenticatedAccess,
    #[serde(rename = "domain/axfr")]
    DomainAxfr,
    #[serde(rename = "domain/cname")]
    DomainCname,
    #[serde(rename = "domain/dmarc")]
    DomainDmarc,
    #[serde(rename = "domain/spf")]
    DomainSpf,
    #[serde(rename = "domain/subdomains")]
    DomainSubdomains,
    #[serde(rename = "domain/takeover")]
    DomainTakeover,
    #[serde(rename = "domain/whois")]
    DomainWhois,
    #[serde(rename = "http/atlassian/cve-2017-9506")]
    HttpAtlassianCve20179506,
    #[serde(rename = "http/cadvisor/unauthenticated-access")]
    HttpCadvisorUnauthenticatedAccess,
    #[serde(rename = "http/consul/unauthenticated-access")]
    HttpConsulUnauthenticatedAccess,
    #[serde(rename = "http/drupal/cve-2018-7600")]
    HttpDrupalCve20187600,
    #[serde(rename = "http/elasticsearch/unauthenticated-access")]
    HttpElasticsearchUnauthenticatedAccess,
    #[serde(rename = "http/etcd/unauthenticated-access")]
    HttpEtcdUnauthenticatedAccess,
    #[serde(rename = "http/yaheiphp/unauthenticated-access")]
    HttpYaheiphpUnauthenticatedAccess,
    #[serde(rename = "http/traefik/dashboard-unauthenticated-access")]
    HttpTraefikDashboardUnauthenticatedAccess,
    #[serde(rename = "http/prometheus/dashboard-unauthenticated-access")]
    HttpPrometheusDashboardUnauthenticatedAccess,
    #[serde(rename = "http/kibana/unauthenticated-access")]
    HttpKibanaUnauthenticatedAccess,
    #[serde(rename = "http/jetty/cve-2015-2080")]
    HttpJettyCve20152080,
    #[serde(rename = "http/gitlab/open-registration")]
    HttpGitlabOpenRegistration,
    #[serde(rename = "http/git/config-disclosure")]
    HttpGitConfigDisclosure,
    #[serde(rename = "http/git/directory-disclosure")]
    HttpGitDirectoryDisclosure,
    #[serde(rename = "http/git/head-disclosure")]
    HttpGitheadDisclosure,
}

impl std::fmt::Display for ModuleName {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", serde_json::to_string(self).expect("error serializing ModuleName"))
    }
}
