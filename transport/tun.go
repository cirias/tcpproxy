package transport

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os/exec"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/tun"

	"github.com/golang/glog"

	"github.com/cirias/tcpproxy/tcpip"
)

type TCPState struct {
	state byte
	seq   int
}

var tunRouteTable = "400"

const (
	TCPSynSent byte = 1 + iota
	TCPFinWait
	TCPLastAck
)

type TUN struct {
	tun      tun.Device
	tunIP    net.IP
	tunIPNet *net.IPNet
}

func NewTUN(name, tunAddr string) (*TUN, error) {
	tunIP, tunIPNet, err := net.ParseCIDR(tunAddr)
	if err != nil {
		return nil, fmt.Errorf("could not parse tunAddr: %w", err)
	}

	tun, err := tun.CreateTUN(name, 1420)
	if err != nil {
		return nil, fmt.Errorf("could not create TUN device: %w", err)
	}

	tunName, err := tun.Name()
	if err != nil {
		return nil, fmt.Errorf("could not get TUN device name: %w", err)
	}

	if err := exec.Command("ip", "address", "add", tunAddr, "dev", tunName).Run(); err != nil {
		return nil, fmt.Errorf("could not add IP %s to %s: %w", tunAddr, tunName, err)
	}

	if err := exec.Command("ip", "link", "set", "dev", tunName, "up").Run(); err != nil {
		return nil, fmt.Errorf("could not set %s up: %w", tunName, err)
	}

	return &TUN{
		tun:      tun,
		tunIP:    tunIP,
		tunIPNet: tunIPNet,
	}, nil
}

func (t *TUN) EnableDefaultRoute() error {
  tunName, err := t.tun.Name()
  if err != nil {
    return fmt.Errorf("could not get name of tun: %w", err)
  }

	if err := exec.Command("ip", "rule", "add", "not", "fwmark", fmt.Sprint(tcpproxyBypassMark), "table", tunRouteTable).Run(); err != nil {
		return fmt.Errorf("could not set bypass rule: %w", err)
	}

	if err := exec.Command("ip", "route", "add", "default", "via", t.tunIP.String(), "dev", tunName, "src", t.tunIP.String(), "table", tunRouteTable).Run(); err != nil {
		return fmt.Errorf("could not set route table for tun device: %w", err)
	}

  return nil
}

func (t *TUN) ReadPackets(tcpl *TUNTCPListener, ipl *TUNIPListener) error {
	defer func() {
		if tcpl != nil {
			close(tcpl.pktCh)
		}
		if ipl != nil {
			close(ipl.pktCh)
		}
	}()

	for {
		buf := allocateBuffer()
		if _, err := buf.ReadFrom(t.tun); err != nil {
			return err
		}

		ip := tcpip.IPPacket(buf.PacketBytes())
		ip4 := ip.IPv4Packet()
		if ip4 == nil {
			releaseBuffer(buf)
			continue
		}

		if tcpl != nil {
			if ip4.Protocol() == tcpip.ProtocolTCP {
				tcpl.pktCh <- buf
				continue
			}
		}

		if ipl != nil {
			ipl.pktCh <- buf
		}
	}
}

func (t *TUN) NewTCPListener(paddr string, lport int) (*TUNTCPListener, error) {
  var proxyIP net.IP
  if paddr == "" {
    tunip := t.tunIP.To4()
    proxyIP = net.IPv4(tunip[0], tunip[1], tunip[2], tunip[3]+10)
  } else {
    proxyIP = net.ParseIP(paddr)
    if proxyIP == nil {
      return nil, fmt.Errorf("could not parse paddr")
    }
  }

	if !t.tunIPNet.Contains(proxyIP) {
		return nil, fmt.Errorf("paddr is not within range of tunAddr")
	}

  laddr := &net.TCPAddr{
    IP: t.tunIP,
    Port: lport,
  }
  listener, err := net.ListenTCP("tcp", laddr)
	if err != nil {
		return nil, fmt.Errorf("could not create TCP listener: %w", err)
	}

	l := &TUNTCPListener{
		listener:          listener,
		tun:               t.tun,
		tunIP:             t.tunIP,
		proxyIP:           proxyIP,
		mapSportDaddr:     make(map[uint16]*net.TCPAddr),
		mapSportConnState: make(map[uint16]*TCPState),
		pktCh:             make(chan *PacketBuf, 0),
	}
	go func() {
		if err := l.mapTCPPackets(); err != nil {
			glog.Fatalln(err)
		}
	}()

	return l, nil
}

type TUNTCPListener struct {
	tun   tun.Device
	tunIP net.IP

	proxyIP  net.IP
	listener net.Listener

  proxyToState  map[[4]byte]map[uint16]*TCPState 

  // src ip -> (src port -> dst address)
  proxyToSrcDst      map[[4]byte]struct{
    srcIP net.IP
    portToDst map[uint16]*net.TCPAddr
  }
	sourcesMutex sync.RWMutex
  srcToProxy      map[[4]byte]net.IP
  

	pktCh chan *PacketBuf
}

func (l *TUNTCPListener) Accept() (Handshaker, error) {
	conn, err := l.listener.Accept()
	if err != nil {
		return nil, fmt.Errorf("could not accept TCP connection: %w", err)
	}

	return &TUNTCPHandshaker{conn, l}, nil
}

func (l *TUNTCPListener) Close() error {
	return l.listener.Close()
}

func (l *TUNTCPListener) Addr() net.Addr {
	return l.listener.Addr()
}

func (l *TUNTCPListener) tcpDaddr(port uint16) *net.TCPAddr {
	l.mapSportDaddrMutex.RLock()
	defer l.mapSportDaddrMutex.RUnlock()
	return l.mapSportDaddr[port]
}

func (l *TUNTCPListener) mapTCPPackets() error {
	for buf := range l.pktCh {
		if err := l.mapOneTCPPacket(buf); err != nil {
			return err
		}
	}
	return nil
}

/*
 * Tun Device Address: 192.168.200.1/24
 * TCP Server Address: 192.168.200.1:12345
 *
 * |--------| 192.168.200.1:56789 -> 1.1.1.1:443 |-----| 192.168.200.2:56789 -> 192.168.200.1:12345 |------------|
 * | Client |                                    | Tun |                                            | TCP Server |
 * |--------| 192.168.200.1:56789 <- 1.1.1.1:443 |-----| 192.168.200.2:56789 <- 192.168.200.1:12345 |------------|
 */
func (l *TUNTCPListener) mapOneTCPPacket(buf *PacketBuf) error {
	defer releaseBuffer(buf)

	ip := tcpip.IPPacket(buf.PacketBytes())
	ip4 := ip.IPv4Packet()
	if ip4 == nil {
		return nil
	}

	tcp := ip4.TransportPacket().(tcpip.TCPPacket)
	if tcp == nil {
		return nil
	}

	laddr := l.listener.Addr().(*net.TCPAddr)

	srcIP := ip4.SrcIP()
	dstIP := ip4.DstIP()
	srcPort := tcp.SrcPort()
	dstPort := tcp.DstPort()

	if srcIP.Equal(laddr.IP) && int(srcPort) == laddr.Port {
		// translate packets came from TCP server
		// NOTE: l.tunIP and laddr.IP are the same
		l.mapSportDaddrMutex.RLock()
		oaddr := l.mapSportDaddr[dstPort]
		l.mapSportDaddrMutex.RUnlock()
		if oaddr == nil {
			return nil
		}

		l.handleTermination(&tcp, dstPort, srcIP, srcPort)

		ip4.SetSrcIP(oaddr.IP)
		tcp.SetSrcPort(uint16(oaddr.Port))
		ip4.SetDstIP(l.tunIP)
	} else if srcIP.Equal(l.tunIP) {
		// translate packets came from kernel TCP stack
		if tcp.SYN() && !tcp.ACK() {
			glog.Infof("initialize connection %s:%d to %s:%d", l.tunIP, srcPort, dstIP, dstPort)
      ipbuf := [4]byte{srcIP[0], srcIP[1], srcIP[2], srcIP[3]}
			l.mapSrcState[ipbuf][srcPort] = &TCPState{TCPSynSent, 0}
			dst := make(net.IP, len(dstIP))
			copy(dst, dstIP)
			l.mapSportDaddrMutex.Lock()
			l.mapSportDaddr[srcPort] = &net.TCPAddr{IP: dst, Port: int(dstPort)}
			l.mapSportDaddrMutex.Unlock()
		}

		l.handleTermination(&tcp, srcPort, srcIP, srcPort)

		ip4.SetSrcIP(l.proxyIP)
		ip4.SetDstIP(laddr.IP)
		tcp.SetDstPort(uint16(laddr.Port))
	}

	ip4.UpdateChecksum()
	tcp.UpdateChecksum(ip4)

	_, err := buf.WriteTo(l.tun)
	return err
}

func (l *TUNTCPListener) handleTermination(tcp *tcpip.TCPPacket, port uint16, srcIP net.IP, srcPort uint16) {
	s := l.mapSportConnState[port]
	if s == nil {
		return
	}

	if tcp.RST() || tcp.ACK() && s.state == TCPLastAck && tcp.ACKNum() == s.seq+1 {
		glog.Infof("terminate connection from %s:%d", l.tunIP, port)
		l.mapSportDaddrMutex.Lock()
		delete(l.mapSportDaddr, port)
		l.mapSportDaddrMutex.Unlock()

		delete(l.mapSportConnState, port)
	} else if tcp.FIN() {
		glog.V(1).Infof("FIN from %s:%d", srcIP, srcPort)

		switch s.state {
		case TCPSynSent:
			s.state = TCPFinWait
		case TCPFinWait:
			s.state = TCPLastAck
			s.seq = tcp.SeqNum()
		}
	}
}

type TUNTCPHandshaker struct {
	net.Conn
	listener *TUNTCPListener
}

func (h *TUNTCPHandshaker) Handshake() (conn net.Conn, raddr net.Addr, err error) {
	saddr := h.Conn.RemoteAddr().(*net.TCPAddr)

	addr := h.listener.tcpDaddr(uint16(saddr.Port))
	if addr == nil {
		return nil, nil, fmt.Errorf("no original address found for port %d", saddr.Port)
	}
	return h.Conn, addr, nil
}

func (t *TUN) NewIPListener() *TUNIPListener {
	return &TUNIPListener{
		tun:   t.tun,
		pktCh: make(chan *PacketBuf, 0),
		mutex: &sync.Mutex{},
	}
}

type TUNIPListener struct {
	tun   tun.Device
	pktCh chan *PacketBuf
	mutex *sync.Mutex
}

func (l *TUNIPListener) Accept() (Handshaker, error) {
	l.mutex.Lock()

	buf, ok := <-l.pktCh
	if !ok {
		return nil, io.EOF
	}

	return &TUNIPHandshaker{
		Conn: &TUNIPConn{
			mutex: l.mutex,
			r: &PacketReader{
				pktCh:    l.pktCh,
				firstPkt: buf,
			},
			w: l.tun,
		},
	}, nil
}

func (l *TUNIPListener) Close() error {
	l.mutex.Lock()
  return nil
}

type TUNIPHandshaker struct {
	Conn *TUNIPConn
}

func (h *TUNIPHandshaker) RemoteAddr() net.Addr {
	return h.Conn.RemoteAddr()
}

func (h *TUNIPHandshaker) Handshake() (conn net.Conn, raddr net.Addr, err error) {
	raddr = &TUNAddr{}
	return h.Conn, raddr, nil
}

type PacketReader struct {
	pktCh            <-chan *PacketBuf
	firstPkt         *PacketBuf
	readFirstPktOnce sync.Once
}

func (r *PacketReader) Read(p []byte, offset int) (int, error) {
	n := 0
	r.readFirstPktOnce.Do(func() {
		defer releaseBuffer(r.firstPkt)
		n = copy(p[offset:], r.firstPkt.PacketBytes())
		r.firstPkt = nil
	})
	if n > 0 {
		return n, nil
	}

	buf, ok := <-r.pktCh
	if !ok {
		return 0, io.EOF
	}
	defer releaseBuffer(buf)

	n = copy(p[offset:], buf.PacketBytes())
	return n, nil
}

func (t *TUN) NewIPDialer() *TUNIPDialer {
	return &TUNIPDialer{
		mutex: &sync.Mutex{},
    tun: t.tun,
	}
}

type TUNIPDialer struct {
  tun tun.Device
	mutex *sync.Mutex
}

func (d *TUNIPDialer) Dial(raddr net.Addr) (net.Conn, error) {
  d.mutex.Lock()

	return &TUNIPConn{
		mutex: d.mutex,
		r:   d.tun,
    w: d.tun,
	}, nil
}

type TUNIPConn struct {
	mutex *sync.Mutex

	r    OffsetReader
	w    OffsetWriter
	wbuf bytes.Buffer
}

func (c *TUNIPConn) Read(p []byte) (int, error) {
	n, err := c.r.Read(p, 4)
	p[2] = 0
	p[3] = 0
	binary.BigEndian.PutUint16(p[:2], uint16(n))
	return n + 4, err
}

func (c *TUNIPConn) Write(b []byte) (int, error) {
	c.wbuf.Write(b)
	for {
		if c.wbuf.Len() < 4 {
			return len(b), nil
		}

		n := int(binary.BigEndian.Uint16(c.wbuf.Bytes()[:2]))
		if c.wbuf.Len() < 4+n {
			break
		}

		if _, err := c.w.Write(c.wbuf.Next(4+n), 4); err != nil {
			return len(b), err
		}
	}

	// TODO optimize
	remain := c.wbuf.Bytes()
	c.wbuf.Reset()
	c.wbuf.Write(remain)

	return len(b), nil
}

func (c *TUNIPConn) Close() error {
	c.mutex.Unlock()
	return nil
}

func (c *TUNIPConn) LocalAddr() net.Addr {
	return tunLocalAddr
}

func (c *TUNIPConn) RemoteAddr() net.Addr {
	return tunRemoteAddr
}

func (c *TUNIPConn) SetDeadline(t time.Time) error {
	panic("not implemented")
}

func (c *TUNIPConn) SetReadDeadline(t time.Time) error {
	panic("not implemented")
}

func (c *TUNIPConn) SetWriteDeadline(t time.Time) error {
	panic("not implemented")
}

type TUNAddr struct{}

func (a *TUNAddr) Network() string {
	return "tun_if"
}

func (a *TUNAddr) String() string {
	return a.Network()
}

type TUNRemoteAddr struct{}

func (a *TUNRemoteAddr) Network() string {
	return ""
}

func (a *TUNRemoteAddr) String() string {
	return "kernel/tun"
}

type TUNLocalAddr struct{}

func (a *TUNLocalAddr) Network() string {
	return ""
}

func (a *TUNLocalAddr) String() string {
	return "user/tun"
}

var tunRemoteAddr = &TUNRemoteAddr{}
var tunLocalAddr = &TUNLocalAddr{}

type OffsetReader interface {
	Read([]byte, int) (int, error)
}

type OffsetWriter interface {
	Write([]byte, int) (int, error)
}
