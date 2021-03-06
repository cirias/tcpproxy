package transport

import (
	"fmt"
	"net"

	"github.com/golang/glog"
)

type RedirectTCPListener struct {
	net.Listener
}

func ListenRedirectTCP(address string) (*RedirectTCPListener, error) {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("could not listen TCP: %w", err)
	}

	return &RedirectTCPListener{listener}, nil
}

func (l *RedirectTCPListener) Accept() (Handshaker, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, fmt.Errorf("could not accept TCP connection: %w", err)
	}

	return &RedirectTCPHandshaker{conn}, nil
}

type RedirectTCPHandshaker struct {
	net.Conn
}

func (c *RedirectTCPHandshaker) Handshake() (conn net.Conn, raddr net.Addr, err error) {
	defer func() {
		if err != nil {
			glog.Info("close connection")
			_ = c.Conn.Close()
		}
	}()

	dst, err := GetOriginalDestination(c.Conn)
	if err != nil {
		return nil, nil, fmt.Errorf("could not get original destination: %w", err)
	}

	return c.Conn, dst, nil
}
