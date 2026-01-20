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

type CertReloader struct {
	certFile          string
	keyFile           string
	cachedCert        *tls.Certificate
	cachedCertModTime time.Time
}

func (cr *CertReloader) GetCertificate(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
	stat, err := os.Stat(cr.keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed checking key file modification time: %w", err)
	}

	if cr.cachedCert == nil || stat.ModTime().After(cr.cachedCertModTime) {
		pair, err := tls.LoadX509KeyPair(cr.certFile, cr.keyFile)
		if err != nil {
			return nil, fmt.Errorf("failed loading tls key pair: %w", err)
		}

		cr.cachedCert = &pair
		cr.cachedCertModTime = stat.ModTime()
	}

	return cr.cachedCert, nil
}

func ListenTLSTunnelWithCert(secret, laddr, faddr string, certFile, keyFile, caCertFile string) (*TunnelListener, error) {
	certReloader := &CertReloader{certFile: certFile, keyFile: keyFile}

	var clientCAs *x509.CertPool
	if caCertFile != "" {
		caCertPEMBlock, err := os.ReadFile(caCertFile)
		if err != nil {
			return nil, fmt.Errorf("could not read CA cert file %s: %w", caCertFile, err)
		}
		clientCAs = x509.NewCertPool()
		if ok := clientCAs.AppendCertsFromPEM(caCertPEMBlock); !ok {
			return nil, fmt.Errorf("could not append certs to client CAs")
		}
	}

	config := &tls.Config{
		NextProtos:     NextProtos,
		GetCertificate: certReloader.GetCertificate,
		ClientCAs:      clientCAs,
	}

	return ListenTLSTunnel(secret, laddr, faddr, config)
}

func ListenTLSTunnel(secret, laddr, faddr string, config *tls.Config) (*TunnelListener, error) {
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
		listener:     &TLSListener{listener.(*net.TCPListener), config},
		secret:       secret,
		fallbackAddr: fallbackAddr,
	}

	glog.Infof("created TLS Tunnel listener on %s", listener.Addr())

	return tl, nil
}

type TLSListener struct {
	*net.TCPListener
	config *tls.Config
}

func (l *TLSListener) Accept() (c net.Conn, err error) {
	conn, err := l.TCPListener.AcceptTCP()
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = conn.Close()
		}
	}()

	if err := conn.SetKeepAlive(true); err != nil {
		return nil, fmt.Errorf("could not set keepalive: %w", err)
	}

	if err := conn.SetKeepAlivePeriod(60 * time.Second); err != nil {
		return nil, fmt.Errorf("could not set keepalive period: %w", err)
	}

	glog.V(1).Infof("enabled keekalive on connection from %s", conn.RemoteAddr())

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

	dialer := &tls.Dialer{
		NetDialer: netDialer,
		Config:    config,
	}

	glog.Infof("created Tunnel dialer to %s", raddr)

	return &TunnelDialer{
		netDialer:  dialer,
		serverAddr: raddr,
		secret:     secret,
	}, nil
}
