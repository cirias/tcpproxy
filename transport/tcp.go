package transport

import (
	"net"
)

type TCPDialer struct {
}

func (d *TCPDialer) Dial(raddr net.Addr) (net.Conn, error) {
	return net.Dial("tcp", raddr.String())
}
