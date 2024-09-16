package transport

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
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

type HostMatcher struct {
	suffixes []string
}

func NewHostMatcherFromFile(filepath string) (*HostMatcher, error) {
	f, err := os.Open(filepath)
	if err != nil {
		return nil, fmt.Errorf("could not open file: %w", err)
	}
	defer f.Close()

	suffixes := make([]string, 0)

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}

		log.Printf("add suffix: %s", line)
		suffixes = append(suffixes, line)
	}

	matcher := &HostMatcher{suffixes}
	return matcher, nil
}

func (m *HostMatcher) Matches(host string) bool {
	for _, suf := range m.suffixes {
		if strings.HasSuffix(host, suf) {
			log.Printf("host %s matches suffix %s", host, suf)
			return true
		}
	}
	return false
}

// SplitHostPort
