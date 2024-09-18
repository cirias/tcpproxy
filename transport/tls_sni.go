package transport

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
)

type TLSSNIListener struct {
	Listener
	sniHosts *HostMatcher
}

func NewTLSSNIListener(listener Listener, sniHostsFilepath string) (*TLSSNIListener, error) {
	sniHosts, err := NewHostMatcherFromFile(sniHostsFilepath)
	if err != nil {
		return nil, fmt.Errorf("could not create hosts matcher from file: %w", err)
	}

	return &TLSSNIListener{Listener: listener, sniHosts: sniHosts}, nil
}

func (l *TLSSNIListener) Accept() (Handshaker, error) {
	hs, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	return &TLSSNIHandshaker{Handshaker: hs, sniHosts: l.sniHosts}, nil
}

type TLSSNIHandshaker struct {
	Handshaker
	sniHosts *HostMatcher
}

func (hs *TLSSNIHandshaker) Handshake() (net.Conn, net.Addr, error) {
	conn, raddr, err := hs.Handshaker.Handshake()
	if err != nil {
		return nil, nil, err
	}

	buf := &bytes.Buffer{}

	teeReader := io.TeeReader(conn, buf)

	helperConn := &TLSSNIClientHelloInfoConn{
		Conn:   conn,
		reader: teeReader,
	}

	var serverName string
	tlsConfig := &tls.Config{
		GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
			serverName = info.ServerName
			return nil, fmt.Errorf("just for getting the server name")
		},
	}

	tlsConn := tls.Server(helperConn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		log.Println(err)
	}

	replayConn := &TLSSNIConn{Conn: conn, buffer: buf}

	if serverName == "" {
		return replayConn, raddr, nil
	}

	log.Printf("TLS server name: %s", serverName)

	if !hs.sniHosts.Matches(serverName) {
		return replayConn, raddr, nil
	}

	tcpAddr, err := net.ResolveTCPAddr(raddr.Network(), raddr.String())
	if err != nil {
		return nil, nil, fmt.Errorf("could not resolve TCP address: %w", err)
	}

	return replayConn, &HostAddr{network: "tcp", hostname: serverName, port: tcpAddr.Port}, nil
}

type TLSSNIClientHelloInfoConn struct {
	net.Conn
	reader io.Reader
}

func (c *TLSSNIClientHelloInfoConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

func (c *TLSSNIClientHelloInfoConn) Write(b []byte) (int, error) {
	return 0, fmt.Errorf("write should not be called")
}

func (c *TLSSNIClientHelloInfoConn) Close() error {
	return fmt.Errorf("close should not be called")
}

type HostAddr struct {
	network  string
	hostname string
	port     int
}

func (a *HostAddr) Network() string {
	return a.network
}

func (a *HostAddr) String() string {
	return net.JoinHostPort(a.hostname, strconv.Itoa(a.port))
}

type TLSSNIConn struct {
	net.Conn
	buffer *bytes.Buffer
}

func (c *TLSSNIConn) Read(b []byte) (int, error) {
	if c.buffer.Len() > 0 {
		return c.buffer.Read(b)
	}

	return c.Conn.Read(b)
}
