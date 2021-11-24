package transport

import (
	"net"
)

type TCPDialer struct {
	laddr *net.TCPAddr
}

func (d *TCPDialer) Dial(raddr *net.TCPAddr) (net.Conn, error) {
	return net.DialTCP("tcp", d.laddr, raddr)
}
