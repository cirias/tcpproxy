package transport

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/golang/glog"
)

type TunnelInitialPacket struct {
	Secret  string
	DstAddr net.Addr
	Payload []byte
}

type decodeError struct {
	error
	scanned *bytes.Buffer
}

func (pkt *TunnelInitialPacket) Decode(r io.Reader) (err error) {
	scanned := new(bytes.Buffer)
	defer func() {
		if err != nil {
			_, _ = scanned.Write(pkt.Payload)
			err = &decodeError{err, scanned}
		}
	}()

	s := bufio.NewScanner(r)
	s.Split(func(data []byte, atEOF bool) (int, []byte, error) {
		advance, token, err := bufio.ScanLines(data, atEOF)

		_, _ = scanned.Write(data[:advance])

		// a little hack to get the remining buffered bytes
		pkt.Payload = data[advance:]
		return advance, token, err
	})

	{
		if ok := s.Scan(); !ok {
			return fmt.Errorf("scan ended while reading secret hash: %w", s.Err())
		}
		line := s.Text()

		if strings.HasSuffix(line, " HTTP/1.1") || strings.HasSuffix(line, " HTTP/2.0") {
			return fmt.Errorf("http preface received")
		}
		pkt.Secret = line
	}

	{
		if ok := s.Scan(); !ok {
			return fmt.Errorf("scan ended while reading destination address: %w", s.Err())
		}
		line := s.Bytes()

		i := bytes.IndexByte(line, ':')
		if i < 0 {
			return fmt.Errorf("could not find ':' in line: %s", line)
		}

		network := string(line[:i])
		address := string(line[i+1:])
		switch network {
		case "tcp", "tcp4", "tcp6":
			addr, err := net.ResolveTCPAddr(network, address)
			if err != nil {
				return fmt.Errorf("could not resolve TCP address (%s, %s): %w", network, address, err)
			}
			pkt.DstAddr = addr
		case "tun_if":
			pkt.DstAddr = &TUNAddr{}
		default:
			return fmt.Errorf("unknown network: %s", network)
		}
	}

	return nil
}

func (pkt *TunnelInitialPacket) Encode(w io.Writer) error {
	if _, err := w.Write([]byte(pkt.Secret + "\r\n")); err != nil {
		return fmt.Errorf("could not write secret hash: %w", err)
	}

	if _, err := w.Write([]byte(pkt.DstAddr.Network() + ":" + pkt.DstAddr.String() + "\r\n")); err != nil {
		return fmt.Errorf("could not write destination address: %w", err)
	}

	if _, err := w.Write(pkt.Payload); err != nil {
		return fmt.Errorf("could not write payload: %w", err)
	}

	return nil
}

type TunnelListener struct {
	listener     net.Listener
	secret       string
	fallbackAddr net.Addr
}

func (l *TunnelListener) Accept() (Handshaker, error) {
	conn, err := l.listener.Accept()
	if err != nil {
		return nil, fmt.Errorf("could not accept tls connection: %w", err)
	}

	return &TunnelServerHandshaker{conn, l}, nil
}

func (l *TunnelListener) Close() error {
	return l.listener.Close()
}

func (l *TunnelListener) Addr() net.Addr {
	return l.listener.Addr()
}

var DefaultHandshakeTimeout = 5 * time.Second

type TunnelServerHandshaker struct {
	net.Conn
	listener *TunnelListener
}

func (c *TunnelServerHandshaker) Handshake() (conn net.Conn, raddr net.Addr, err error) {
	switch conn := c.Conn.(type) {
	case *tls.Conn:
		ctx, cancel := context.WithTimeout(context.Background(), DefaultHandshakeTimeout)
		defer cancel()
		if err := conn.HandshakeContext(ctx); err != nil {
			return nil, nil, fmt.Errorf("could not handshake TLS: %w", err)
		}
	}

	defer func() {
		if err != nil {
			_ = c.Conn.Close()
		}
	}()

	if err := c.Conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return nil, nil, fmt.Errorf("could not set read dead line for the initial packet: %w", err)
	}

	pkt := new(TunnelInitialPacket)
	if err := pkt.Decode(c.Conn); err != nil {
		if pkt.Secret == c.listener.secret || c.listener.fallbackAddr == nil {
			return nil, nil, fmt.Errorf("could not decode initial packet: %w", err)
		}

		glog.Infof("fallback %s -> %s: %s", c.Conn.RemoteAddr(), c.listener.fallbackAddr, err)
		de := err.(*decodeError)
		return &TunnelServerConn{c.Conn, de.scanned}, c.listener.fallbackAddr, nil
	}

	if pkt.Secret != c.listener.secret {
		return nil, nil, fmt.Errorf("invalid secret")
	}

	return &TunnelServerConn{c.Conn, bytes.NewBuffer(pkt.Payload)}, pkt.DstAddr, nil
}

type TunnelServerConn struct {
	net.Conn
	buf *bytes.Buffer
}

func (c *TunnelServerConn) Read(b []byte) (int, error) {
	// FIXME concurrency safe
	if c.buf != nil {
		n, err := c.buf.Read(b)
		if err == nil {
			return n, nil
		}

		if err != io.EOF {
			return n, err
		}

		c.buf = nil
	}

	return c.Conn.Read(b)
}

type TunnelDialer struct {
	netDialer  NetDialer
	serverAddr string
	secret     string
}

func (d *TunnelDialer) Dial(raddr net.Addr) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultHandshakeTimeout)
	defer cancel()

	conn, err := d.netDialer.DialContext(ctx, "tcp", d.serverAddr)
	if err != nil {
		return nil, fmt.Errorf("could not dial connection: %w", err)
	}

	pkt := &TunnelInitialPacket{
		Secret:  d.secret,
		DstAddr: raddr,
		Payload: nil,
	}

	return &TunnelClientConn{Conn: conn, pkt: pkt}, nil
}

type TunnelClientConn struct {
	net.Conn
	pkt          *TunnelInitialPacket
	writePktOnce sync.Once
}

func (c *TunnelClientConn) Write(b []byte) (int, error) {
	var e error
	var writePktSuccess bool
	c.writePktOnce.Do(func() {
		c.pkt.Payload = b

		var buf bytes.Buffer
		if err := c.pkt.Encode(&buf); err != nil {
			e = fmt.Errorf("could not encode initial packet: %w", err)
			return
		}

		if _, err := c.Conn.Write(buf.Bytes()); err != nil {
			e = fmt.Errorf("could not write initial packet to connection: %w", err)
			return
		}

		c.pkt = nil
		writePktSuccess = true
	})
	if e != nil {
		return 0, e
	}
	if writePktSuccess {
		return len(b), nil
	}

	return c.Conn.Write(b)
}
