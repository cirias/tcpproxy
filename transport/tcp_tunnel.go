package transport

import (
	"fmt"
	"net"
	"syscall"

	"github.com/golang/glog"
)

func ListenTCPTunnel(secret, laddr, faddr string) (*TunnelListener, error) {
	listener, err := net.Listen("tcp", laddr)
	if err != nil {
		return nil, fmt.Errorf("could not listen TCP %s: %w", laddr, err)
	}

	var fallbackAddr net.Addr
	if faddr != "" {
		fallbackAddr, err = net.ResolveTCPAddr("tcp", faddr)
		if err != nil {
			return nil, fmt.Errorf("could not resolve fallback address %s: %w", faddr, err)
		}
	}

	tl := &TunnelListener{
		listener:     listener,
		secret:       secret,
		fallbackAddr: fallbackAddr,
	}

	glog.Infof("created TCP Tunnel listener on %s", listener.Addr())

	return tl, nil
}

func NewTCPDialer(secret, laddr, raddr string) (*TunnelDialer, error) {
	netDialer := &net.Dialer{
		Control: func(_, _ string, c syscall.RawConn) error {
			var sockErr error
			err := c.Control(func(fd uintptr) {
				sockErr = SetSocketMark(int(fd), tcpproxyBypassMark)
			})
			if sockErr != nil {
				return sockErr
			}
			return err
		},
	}

	if laddr != "" {
		addr, err := net.ResolveTCPAddr("tcp", laddr)
		if err != nil {
			return nil, fmt.Errorf("could not resolve local address %s: %w", laddr, err)
		}
		netDialer.LocalAddr = addr
	}

	glog.Infof("created Tunnel dialer to %s", raddr)

	return &TunnelDialer{
		netDialer:  netDialer,
		serverAddr: raddr,
		secret:     secret,
	}, nil
}
