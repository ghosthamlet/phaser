package ports

import (
	"fmt"
	"net"
	"time"

	"github.com/bloom42/phaser/phaser/findings"
)

func Scan(ip string, ports []uint16, protocol string, timeout time.Duration) []findings.Port {
	ret := make([]findings.Port, len(ports))

	for i, portID := range ports {
		state := "closed"
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, portID), timeout)
		if err == nil {
			conn.Close()
			state = "open"
		}
		port := findings.Port{
			ID:       portID,
			State:    state,
			Protocol: protocol,
		}
		ret[i] = port
	}

	return ret
}
