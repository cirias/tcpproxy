package transport

import (
	"fmt"
	"net"
)

type TUNTCPDialer struct {
	TCP *TCPDialer
	IP  *TUNIPDialer
}

func (d *TUNTCPDialer) Dial(raddr net.Addr) (net.Conn, error) {
	switch raddr.Network() {
	case "tcp", "tcp4", "tcp6":
		return d.TCP.Dial(raddr)
	case "tun_if":
		return d.IP.Dial(raddr)
	default:
		return nil, fmt.Errorf("network is not tcp: %s", raddr.Network())
	}
}
