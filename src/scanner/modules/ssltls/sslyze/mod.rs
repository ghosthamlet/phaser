/// sslyz module provides structs to ease SSLYZ results parsing
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Scan {
    pub accepted_targets: Vec<AcceptedTarget>,
    pub invalid_targets: Vec<InvalidTarget>,
    pub network_max_retries: i64,
    pub network_timeout: i64,
    pub sslyze_url: String,
    pub sslyze_version: String,
    pub total_scan_time: String,
}

// InvalidTarget is a map where the keys are the targets, and values the errors
type InvalidTarget = HashMap<String, String>;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AcceptedTarget {
    pub commands_results: CommandsResults,
    pub server_info: ServerInfo,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ServerInfo {
    // "client_auth_credentials": null,
    // "http_tunneling_settings": null,
    // "xmpp_to_hostname": null
    pub client_auth_requirement: String,
    pub highest_ssl_version_supported: String,
    pub hostname: String,
    pub ip_address: String,
    pub port: u16,
    pub server_string: String,
    pub ssl_cipher_supported: String,
    pub tls_server_name_indication: String,
    pub tls_wrapped_protocol: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CommandsResults {
    // "compression"
    // "resum"
    // "sslv2"
    // "sslv3"
    // "tlsv1"
    // "tlsv1_1"
    // "tlsv1_2"
    pub certinfo: ResultCertInfo,
    pub fallback: ResultFallback,
    pub heartbleed: ResultHeartbleed,
    pub openssl_ccs: ResultOpenSSLCCS,
    pub reneg: ResultReneg,
    pub robot: ResultRobot,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ResultCertInfo {
    // A lot of fileds are missing
    pub certificate_matches_hostname: bool,
    pub has_anchor_in_certificate_chain: bool,
    pub has_sha1_in_certificate_chain: bool,
    pub is_certificate_chain_order_valid: bool,
    pub is_leaf_certificate_ev: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ResultFallback {
    pub supports_fallback_scsv: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ResultHeartbleed {
    pub is_vulnerable_to_heartbleed: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ResultOpenSSLCCS {
    pub is_vulnerable_to_ccs_injection: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ResultReneg {
    pub accepts_client_renegotiation: bool,
    pub supports_secure_renegotiation: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ResultRobot {
    pub accepts_client_renegotiation: String,
}
