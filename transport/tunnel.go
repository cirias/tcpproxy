package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/golang/glog"
)

type TunnelInitialPacket struct {
	SecretHash [64]byte
	DstAddr    net.TCPAddr
	Payload    []byte
}

func (pkt *TunnelInitialPacket) Decode(r io.Reader) error {
	if _, err := io.ReadFull(r, pkt.SecretHash[:]); err != nil {
		return fmt.Errorf("could not read secret hash: %w", err)
	}

	var iplenBuf [1]byte
	if _, err := io.ReadFull(r, iplenBuf[:]); err != nil {
		return fmt.Errorf("could not read IP length: %w", err)
	}

	iplen := int(iplenBuf[0])
	if iplen != net.IPv4len && iplen != net.IPv6len {
		return fmt.Errorf("invalid length of IP address: %d", iplen)
	}

	pkt.DstAddr.IP = make([]byte, iplen)
	if _, err := io.ReadFull(r, pkt.DstAddr.IP); err != nil {
		return fmt.Errorf("could not read IP: %w", err)
	}

	var uPort uint16
	if err := binary.Read(r, binary.BigEndian, &uPort); err != nil {
		return fmt.Errorf("could not read port: %w", err)
	}
	pkt.DstAddr.Port = int(uPort)

	return nil
}

func (pkt *TunnelInitialPacket) Encode(w io.Writer) error {
	if _, err := w.Write(pkt.SecretHash[:]); err != nil {
		return fmt.Errorf("could not write secret hash: %w", err)
	}

	iplen := len(pkt.DstAddr.IP)
	if iplen != net.IPv4len && iplen != net.IPv6len {
		return fmt.Errorf("invalid length of IP address: %d", iplen)
	}

	if _, err := w.Write([]byte{byte(iplen)}); err != nil {
		return fmt.Errorf("could not write IP length: %w", err)
	}

	if _, err := w.Write(pkt.DstAddr.IP); err != nil {
		return fmt.Errorf("could not write IP address: %w", err)
	}

	if err := binary.Write(w, binary.BigEndian, uint16(pkt.DstAddr.Port)); err != nil {
		return fmt.Errorf("could not write port: %w", err)
	}

	if _, err := w.Write(pkt.Payload); err != nil {
		return fmt.Errorf("could not write payload: %w", err)
	}

	return nil
}

type TunnelListener struct {
	listener   net.Listener
	secretHash [64]byte
}

func (l *TunnelListener) Accept() (Handshaker, error) {
	conn, err := l.listener.Accept()
	if err != nil {
		return nil, fmt.Errorf("could not accept tls connection: %w", err)
	}

	return &TunnelServerHandshaker{conn, &l.secretHash}, nil
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
	secretHash *[64]byte
}

func (c *TunnelServerHandshaker) Handshake() (conn net.Conn, raddr *net.TCPAddr, err error) {
	tlsConn := c.Conn.(*tls.Conn)
	if tlsConn != nil {
		ctx, cancel := context.WithTimeout(context.Background(), DefaultHandshakeTimeout)
		defer cancel()
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return nil, nil, fmt.Errorf("could not handshake TLS: %w", err)
		}
	}

	defer func() {
		if err != nil {
			glog.Info("close connection")
			_ = c.Conn.Close()
		}
	}()

	pkt := new(TunnelInitialPacket)
	if err := pkt.Decode(c.Conn); err != nil {
		return nil, nil, fmt.Errorf("could not decode initial packet: %w", err)
	}

	if bytes.Compare(pkt.SecretHash[:], c.secretHash[:]) != 0 {
		return nil, nil, fmt.Errorf("invalid secret hash")
	}

	return c.Conn, &pkt.DstAddr, nil
}

type TunnelDialer struct {
	netDialer  NetDialer
	serverAddr string
	secretHash [64]byte
}

func (d *TunnelDialer) Dial(raddr *net.TCPAddr) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultHandshakeTimeout)
	defer cancel()

	conn, err := d.netDialer.DialContext(ctx, "tcp", d.serverAddr)
	if err != nil {
		return nil, fmt.Errorf("could not dial connection: %w", err)
	}

	pkt := &TunnelInitialPacket{
		SecretHash: d.secretHash,
		DstAddr:    *raddr,
		Payload:    nil,
	}

	return &TunnelClientConn{conn, pkt, sync.Once{}}, nil
}

type TunnelClientConn struct {
	net.Conn
	pkt          *TunnelInitialPacket
	writePktOnce sync.Once
}

func (c *TunnelClientConn) Write(b []byte) (int, error) {
	var e error
	c.writePktOnce.Do(func() {
		c.pkt.Payload = b

		var buf bytes.Buffer
		if err := c.pkt.Encode(&buf); err != nil {
			e = fmt.Errorf("could not encode initial packet: %w", err)
			return
		}

		if _, err := c.Conn.Write(buf.Bytes()); err != nil {
			e = fmt.Errorf("could not write initial packet to connection: %w", err)
		}
	})
	if e != nil {
		return 0, e
	}
	if c.pkt != nil {
		c.pkt = nil
		return len(b), nil
	}

	return c.Conn.Write(b)
}
