package transport

import (
	"fmt"
	"net"
)

type TCPDialer struct {
}

func (d *TCPDialer) Dial(raddr net.Addr) (net.Conn, error) {
	return net.Dial(raddr.Network(), raddr.String())
}

type IPv6TCPDialer struct {
	ipv6Hosts *HostMatcher
}

func NewIPv6TCPDialer(ipv6HostsFilepath string) (*IPv6TCPDialer, error) {
	ipv6Hosts, err := NewHostMatcherFromFile(ipv6HostsFilepath)
	if err != nil {
		return nil, fmt.Errorf("could not create ipv6 host matcher: %w", err)
	}

	return &IPv6TCPDialer{ipv6Hosts}, nil
}

func (d *IPv6TCPDialer) Dial(raddr net.Addr) (net.Conn, error) {
	hostport := raddr.String()
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil, fmt.Errorf("could not split host port: %w", err)
	}

	network := "tcp4"
	if d.ipv6Hosts.Matches(host) {
		network = "tcp6"
	}
	return net.Dial(network, hostport)
}
