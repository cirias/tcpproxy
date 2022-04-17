package transport

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/golang/glog"
)

const tcpproxyBypassMark int = 0x00100

var NextProtos = []string{"h2", "http/1.1"}

func ListenTLSTunnelWithCertFile(secret, laddr, faddr, certFile, keyFile, caCertFile string) (*TunnelListener, error) {
	certPEMBlock, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("could not read cert file %s: %w", certFile, err)
	}

	keyPEMBlock, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("could not read cert key file %s: %w", keyFile, err)
	}

	var caCertPEMBlock []byte
	if caCertFile != "" {
		var err error
		caCertPEMBlock, err = os.ReadFile(caCertFile)
		if err != nil {
			return nil, fmt.Errorf("could not read CA cert file %s: %w", caCertFile, err)
		}
	}

	return ListenTLSTunnelWithCert(secret, laddr, faddr, certPEMBlock, keyPEMBlock, caCertPEMBlock)
}

func ListenTLSTunnelWithCert(secret, laddr, faddr string, certBlock, keyBlock, caCertBlock []byte) (*TunnelListener, error) {
	config := &tls.Config{
		NextProtos: NextProtos,
	}

	cert, err := tls.X509KeyPair(certBlock, keyBlock)
	if err != nil {
		return nil, fmt.Errorf("could not load cert: %w", err)
	}

	config.Certificates = []tls.Certificate{cert}

	if caCertBlock != nil {
		clientCAs := x509.NewCertPool()
		if ok := clientCAs.AppendCertsFromPEM(caCertBlock); !ok {
			return nil, fmt.Errorf("could not append certs to client CAs")
		}
		config.ClientCAs = clientCAs
	}

	return ListenTLSTunnel(secret, laddr, faddr, config)
}

func ListenTLSTunnel(secret, laddr, faddr string, config *tls.Config) (*TunnelListener, error) {
	listener, err := net.Listen("tcp", laddr)
	if err != nil {
		return nil, fmt.Errorf("could not listen TLS: %w", err)
	}

	var fallbackAddr net.Addr
	if faddr != "" {
		fallbackAddr, err = net.ResolveTCPAddr("tcp", faddr)
		if err != nil {
			return nil, fmt.Errorf("could not resolve fallback address %s: %w", faddr, err)
		}
	}

	tl := &TunnelListener{
		listener:     &TLSListener{listener.(*net.TCPListener), config},
		secret:       secret,
		fallbackAddr: fallbackAddr,
	}

  glog.Infof("created Tunnel listener on %s", listener.Addr())

	return tl, nil
}

type TLSListener struct {
	*net.TCPListener
	config *tls.Config
}

func (l *TLSListener) Accept() (net.Conn, error) {
	conn, err := l.TCPListener.AcceptTCP()
	if err != nil {
		return nil, err
	}

	if err := conn.SetKeepAlive(true); err != nil {
		return nil, fmt.Errorf("could not set keepalive: %w", err)
	}

	if err := conn.SetKeepAlivePeriod(60 * time.Second); err != nil {
		return nil, fmt.Errorf("could not set keepalive period: %w", err)
	}

	return tls.Server(conn, l.config), nil
}

func NewTLSTunnelDialerWithCertFile(secret, laddr, raddr, serverName, caCertFile string) (*TunnelDialer, error) {
	var caCertPEMBlock []byte
	if caCertFile != "" {
		var err error
		caCertPEMBlock, err = os.ReadFile(caCertFile)
		if err != nil {
			return nil, fmt.Errorf("could not read CA cert file %s: %w", caCertFile, err)
		}
	}

	return NewTLSTunnelDialerWithCert(secret, laddr, raddr, serverName, caCertPEMBlock)
}

func NewTLSTunnelDialerWithCert(secret, laddr, raddr, serverName string, caCertBlock []byte) (*TunnelDialer, error) {
	config := &tls.Config{
		NextProtos:         NextProtos,
		ServerName:         serverName,
		ClientSessionCache: tls.NewLRUClientSessionCache(0),
	}

	if caCertBlock != nil {
		rootCAs := x509.NewCertPool()
		if ok := rootCAs.AppendCertsFromPEM(caCertBlock); !ok {
			return nil, fmt.Errorf("could not append certs to root CAs")
		}
		config.RootCAs = rootCAs
	}

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{
			Control: func(_, _ string, c syscall.RawConn) error {
				var sockErr error
				err := c.Control(func(fd uintptr) {
					sockErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, tcpproxyBypassMark)
				})
				if sockErr != nil {
					return sockErr
				}
				return err
			},
		},
		Config: config,
	}

	if laddr != "" {
		addr, err := net.ResolveTCPAddr("tcp", laddr)
		if err != nil {
			return nil, fmt.Errorf("could not resolve local address %s: %w", laddr, err)
		}
		dialer.NetDialer.LocalAddr = addr
	}

  glog.Infof("created Tunnel dialer to %s", raddr)

	return &TunnelDialer{
		netDialer:  dialer,
		serverAddr: raddr,
		secret:     secret,
	}, nil
}
