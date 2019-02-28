package sslyze

import (
	"encoding/json"
)

// Scan contains all the data for a single sslyze scan.
type Scan struct {
	AcceptedTargets   []AcceptedTarget `json:"accepted_targets"`
	InvalidTargets    []InvalidTarget  `json:"invalid_targets"`
	NetworkMaxRetries int64            `json:"network_max_retries"`
	NetworkTimeout    int64            `json:"network_timeout"`
	SSLyzeURL         string           `json:"sslyze_url"`
	SSLyzeVersion     string           `json:"sslyze_version"`
	TotalScanTime     string           `json:"total_scan_time"`
}

// InvalidTarget is a map where the keys are the targets, and values the errors
type InvalidTarget map[string]string

type AcceptedTarget struct {
	CommandsResults CommandsResults `json:"commands_results"`
	ServerInfo      ServerInfo      `json:"server_info"`
}

type ServerInfo struct {
	// "client_auth_credentials": null,
	// "http_tunneling_settings": null,
	// "xmpp_to_hostname": null
	ClientAuthRequirement      string `json:"client_auth_requirement"`
	HighestSSLVersionSupported string `json:"highest_ssl_version_supported"`
	Hostname                   string `json:"hostname"`
	IPAddress                  string `json:"ip_address"`
	Port                       uint16 `json:"port"`
	ServerString               string `json:"server_string"`
	SSLCipherSupported         string `json:"ssl_cipher_supported"`
	TLSServerNameIndication    string `json:"tls_server_name_indication"`
	TLSWrappedProtocol         string `json:"tls_wrapped_protocol"`
}

type CommandsResults struct {
	CertInfo ResultCertInfo `json:"certinfo"`
	// "compression"
	Fallback   ResultFallback   `json:"fallback"`
	Heartbleed ResultHeartbleed `json:"heartbleed"`
	OpenSSLCCS ResultOpenSSLCCS `json:"openssl_ccs"`
	Reneg      ResultReneg      `json:"reneg"`
	Robot      ResultRobot      `json:"robot"`
	// "resum"
	// "sslv2"
	// "sslv3"
	// "tlsv1"
	// "tlsv1_1"
	// "tlsv1_2"
}

type ResultCertInfo struct {
	// A lot of fileds are missing
	CertificateMatchesHostname   bool `json:"certificate_matches_hostname"`
	HasAnchorInCertificateChain  bool `json:"has_anchor_in_certificate_chain"`
	HasSHA1InCertificateChain    bool `json:"has_sha1_in_certificate_chain"`
	IsCertificateChainOrderValid bool `json:"is_certificate_chain_order_valid"`
	IsLeafCertificateEV          bool `json:"is_leaf_certificate_ev"`
}

type ResultFallback struct {
	SupportFallbackSCSV bool `json:"supports_fallback_scsv"`
}

type ResultHeartbleed struct {
	IsVulnerableToHeartbleed bool `json:"is_vulnerable_to_heartbleed"`
}

type ResultOpenSSLCCS struct {
	IsVulnerableToCcsInjection bool `json:"is_vulnerable_to_ccs_injection"`
}

type ResultReneg struct {
	AcceptsClientRenegotiation  bool `json:"accepts_client_renegotiation"`
	SupportsSecureRenegotiation bool `json:"supports_secure_renegotiation"`
}

type ResultRobot struct {
	RobotResultEnum string `json:"robot_result_enum"`
}

// Parse takes a byte array of sslyze JSON data and unmarshals it into an
// Scan struct.
func Parse(sslyzeOutput []byte) (*Scan, error) {
	r := &Scan{}
	err := json.Unmarshal(sslyzeOutput, r)
	return r, err
}
