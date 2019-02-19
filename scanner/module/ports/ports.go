package ports

import (
	"os/exec"
	"strconv"
	"strings"

	"github.com/bloom42/phaser/common/phaser"
	"github.com/bloom42/phaser/scanner/module"
	"github.com/bloom42/phaser/scanner/module/ports/nmap"
)

type Ports struct{}

func (Ports) Name() string {
	return "ports"
}

func (Ports) Description() string {
	return "scan ports"
}

func (Ports) Author() string {
	return "Sylvain Kerkour <sylvain@kerkour.com>"
}

func (Ports) Version() string {
	return "0.1.0"
}

type Port struct {
	ID       uint16 `json:"id"`
	State    string `json:"state"`
	Protocol string `json:"protocol"`
}

// unique returns a unique subset of the uint16 slice provided.
func unique(input []uint16) []uint16 {
	u := make([]uint16, 0, len(input))
	m := make(map[uint16]bool)

	for _, val := range input {
		if _, ok := m[val]; !ok {
			m[val] = true
			u = append(u, val)
		}
	}

	return u
}

func portsToStr(ports []uint16) string {
	portsStr := make([]string, len(ports))
	for i, port := range ports {
		portsStr[i] = strconv.Itoa(int(port))
	}
	return strings.Join(portsStr, ",")
}

func (ports Ports) Run(scan *phaser.Scan, target *phaser.Target) (module.Result, []error) {
	errs := []error{}
	portsToScan := []uint16{
		1,
		3,
		4,
		6,
		7,
		9,
		13,
		21,        // ftp
		22,        // ssh
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
	}
	portsToScan = unique(portsToScan)
	command := "nmap"
	portsStr := portsToStr(portsToScan)
	commandArgs := []string{"-p", portsStr, "-oX", "-", target.Host, "-dd", "--host-timeout", "2m"}
	ret := []Port{}
	// protocol := "tcp"

	// for i, portID := range portsToScan {
	// 	state := "closed"
	// 	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target.Host, portID), 8*time.Second)
	// 	if err == nil {
	// 		conn.Close()
	// 		state = "open"
	// 	}
	// 	port := Port{
	// 		ID:       portID,
	// 		State:    state,
	// 		Protocol: protocol,
	// 	}
	// 	ret[i] = port
	// }
	out, err := exec.Command(command, commandArgs...).Output()
	if err != nil {
		errs = append(errs, err)
		return ret, errs
		// var errr string
		// if eerr, ok := err.(*exec.ExitError); ok {
		// 	errr = string(eerr.Stderr)
		// } else {
		// 	errr = err.Error()
		// }
		// errs = append(errs, formatError(errr, target.Host, target.Type, nil))
		// return ret
	}

	scanResult, err := nmap.Parse(out)
	if err != nil {
		errs = append(errs, err)
		return ret, errs
	}

	for _, host := range scanResult.Hosts {
		for _, port := range host.Ports {
			if port.State.State != "closed" && port.State.State != "filtered" {
				port := Port{
					ID:       uint16(port.PortId),
					State:    port.State.State,
					Protocol: port.Protocol,
				}
				ret = append(ret, port)
			}
		}
	}

	return ret, errs
}
