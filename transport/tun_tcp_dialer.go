package transport

import (
	"fmt"
	"log"
	"net"
)

type TUNTCPDialer struct {
	TCP Dialer
	IP  Dialer
}

func (d *TUNTCPDialer) Dial(raddr net.Addr) (net.Conn, error) {
	log.Printf("dail %s %s", raddr.Network(), raddr.String())
	switch raddr.Network() {
	case "tcp", "tcp4", "tcp6":
		return d.TCP.Dial(raddr)
	case "tun_if":
		return d.IP.Dial(raddr)
	default:
		return nil, fmt.Errorf("network is not tcp: %s", raddr.Network())
	}
}
