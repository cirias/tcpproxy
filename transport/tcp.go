package transport

import (
	"fmt"
	"net"
)

type TCPDialer struct {
}

func (d *TCPDialer) Dial(raddr net.Addr) (net.Conn, error) {
	switch raddr.Network() {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, fmt.Errorf("network is not tcp: %s", raddr.Network())
	}

	return net.Dial("tcp", raddr.String())
}
