package transport

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"
	"unsafe"

	"github.com/golang/glog"

	"golang.zx2c4.com/wireguard/tun"

	"github.com/cirias/tcpproxy/tcpip"
)

func TUNReadPacketsRoutine(tun tun.Device, tcpl *TUNTCPListener, ipl *TUNIPListener) error {
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
		if _, err := buf.ReadFrom(tun); err != nil {
			return fmt.Errorf("could not read from TUN device: %w", err)
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

func NewTUNTCPListener(tun tun.Device, tunAddr, clientMockIPAddr string, lport int) (*TUNTCPListener, error) {
	tunIP, tunIPNet, err := net.ParseCIDR(tunAddr)
	if err != nil {
		return nil, fmt.Errorf("could not parse tunAddr: %w", err)
	}

	clientMockIP := net.ParseIP(clientMockIPAddr)
	if clientMockIP == nil {
		return nil, fmt.Errorf("could not parse clientMockIPAddr: %w", err)
	}
	if !tunIPNet.Contains(clientMockIP) {
		return nil, fmt.Errorf("clientMockIPAddr is not within range of tunAddr")
	}

	laddr := &net.TCPAddr{
		IP:   tunIP,
		Port: lport,
	}
	listener, err := net.ListenTCP("tcp", laddr)
	if err != nil {
		return nil, fmt.Errorf("could not create TCP listener: %w", err)
	}
	glog.Infof("created TUN TCP listener, clientMockIP=%s laddr=%s", clientMockIP, listener.Addr())

	l := &TUNTCPListener{
		listener: listener,
		tun:      tun,
		tunIP:    tunIP,

		clientMockIP: clientMockIP,

		pktCh: make(chan *PacketBuf, 0),
	}
	glog.Infof("sizeof l.clientPortToDstAddr=%d", unsafe.Sizeof(l.clientPortToDstAddr))

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

	listener net.Listener

	clientMockIP net.IP

	clientPortToDstAddr      [1 << 16]netip.AddrPort // 2M bytes on 64bit, 1536K bytes on 32bit
	clientPortToDstAddrMutex sync.RWMutex

	pktCh chan *PacketBuf
}

func advanceIP(ip net.IP, ipnet *net.IPNet) {
	if x := ip.To4(); x != nil {
		ip = x
	}
	for {
		for i := len(ip) - 1; i >= 0; i-- {
			ip[i]++
			if ip[i] != 0 && ip[i] != 0xff {
				break
			}
			ip[i] = 1
		}
		if ipnet.Contains(ip) {
			break
		}

		netip := ipnet.IP
		if x := netip.To4(); x != nil {
			netip = x
		}
		copy(ip, netip)
	}
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

func (l *TUNTCPListener) tcpDaddr(clientPort int) netip.AddrPort {
	l.clientPortToDstAddrMutex.RLock()
	defer l.clientPortToDstAddrMutex.RUnlock()

	return l.clientPortToDstAddr[clientPort]
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

	if dstIP.Equal(l.clientMockIP) && srcIP.Equal(laddr.IP) && int(srcPort) == laddr.Port {
		// translate packets came from TCP server
		// NOTE: l.tunIP and laddr.IP are the same

		var oaddr netip.AddrPort
		{
			l.clientPortToDstAddrMutex.RLock()
			oaddr = l.clientPortToDstAddr[dstPort]
			l.clientPortToDstAddrMutex.RUnlock()
		}

		ip4.SetSrcIP(oaddr.Addr().AsSlice())
		tcp.SetSrcPort(oaddr.Port())
		ip4.SetDstIP(l.tunIP)
	} else if srcIP.Equal(l.tunIP) {
		// translate packets came from kernel TCP stack

		if tcp.SYN() && !tcp.ACK() {
			glog.Infof("initialize connection state for %s:%d to %s:%d", l.tunIP, srcPort, dstIP, dstPort)

			dst, ok := netip.AddrFromSlice(dstIP)
			if !ok {
				glog.Errorf("could not convert net.IP to netip.Addr: %s", dstIP)
			}

			{
				l.clientPortToDstAddrMutex.Lock()
				l.clientPortToDstAddr[srcPort] = netip.AddrPortFrom(dst, dstPort)
				l.clientPortToDstAddrMutex.Unlock()
			}
		}

		ip4.SetSrcIP(l.clientMockIP)
		ip4.SetDstIP(laddr.IP)
		tcp.SetDstPort(uint16(laddr.Port))
	}

	ip4.UpdateChecksum()
	tcp.UpdateChecksum(ip4)

	_, err := buf.WriteTo(l.tun)
	return err
}

type TUNTCPHandshaker struct {
	net.Conn
	listener *TUNTCPListener
}

func (h *TUNTCPHandshaker) Handshake() (conn net.Conn, raddr net.Addr, err error) {
	saddr := h.Conn.RemoteAddr().(*net.TCPAddr)

	addr := net.TCPAddrFromAddrPort(h.listener.tcpDaddr(saddr.Port))
	if addr == nil {
		h.Conn.Close()
		return nil, nil, fmt.Errorf("no original address found for port %d", saddr.Port)
	}

	return h.Conn, addr, nil
}

func NewTUNIPListener(tun tun.Device) *TUNIPListener {
	return &TUNIPListener{
		tun:   tun,
		pktCh: make(chan *PacketBuf, 0),
		mutex: &sync.Mutex{},
	}
}

type TUNIPListener struct {
	tun   tun.Device
	pktCh chan *PacketBuf
	mutex *sync.Mutex
}

func (l *TUNIPListener) Addr() net.Addr {
	return &TUNAddr{}
}

func (l *TUNIPListener) Accept() (Handshaker, error) {
	ifname, err := l.tun.Name()
	if err != nil {
		return nil, fmt.Errorf("could not get name of TUN device: %w", err)
	}

	l.mutex.Lock()

	buf, ok := <-l.pktCh
	if !ok {
		return nil, io.EOF
	}

	once := new(sync.Once)

	reader := &PacketReader{
		closedCh: make(chan struct{}),
		pktCh:    l.pktCh,
		firstPkt: buf,
	}

	return &TUNIPHandshaker{
		Conn: &TUNIPConn{
			ifname: ifname,
			closeFunc: func() error {
				once.Do(func() {
					reader.Close()
					l.mutex.Unlock()
				})
				return nil
			},
			r: reader,
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
	closedCh         chan struct{}
	pktCh            <-chan *PacketBuf
	firstPkt         *PacketBuf
	readFirstPktOnce sync.Once
}

func (r *PacketReader) Close() {
	close(r.closedCh)
}

func (r *PacketReader) Read(p []byte, offset int) (int, error) {
	n := 0
	r.readFirstPktOnce.Do(func() {
		n = copy(p[offset:], r.firstPkt.PacketBytes())
		releaseBuffer(r.firstPkt)
		r.firstPkt = nil
	})
	if n > 0 {
		return n, nil
	}

	select {
	case <-r.closedCh:
		return 0, io.EOF
	case buf, ok := <-r.pktCh:
		if !ok {
			return 0, io.EOF
		}
		defer releaseBuffer(buf)

		n = copy(p[offset:], buf.PacketBytes())
		return n, nil
	}
}

func NewTUNIPDialer(tun tun.Device) *TUNIPDialer {
	// glog.Infof("created TUN IP dialer on %s", t.name)
	return &TUNIPDialer{
		tun:    tun,
		ipToCh: make(map[netip.Addr]chan *PacketBuf),
	}
}

type TUNIPDialer struct {
	tun tun.Device

	ipToChMutex sync.RWMutex
	ipToCh      map[netip.Addr]chan *PacketBuf

	addr net.Addr
}

func (d *TUNIPDialer) ReadPacketsRoutine() error {
	for {
		buf := allocateBuffer()
		if _, err := buf.ReadFrom(d.tun); err != nil {
			return fmt.Errorf("could not read from TUN device: %w", err)
		}

		ip := tcpip.IPPacket(buf.PacketBytes())
		ip4 := ip.IPv4Packet()
		if ip4 == nil {
			releaseBuffer(buf)
			glog.Warningf("received IPv6 packet from TUN device")
			continue
		}

		dstip, _ := netip.AddrFromSlice(ip4.DstIP())

		d.ipToChMutex.RLock()
		ch, ok := d.ipToCh[dstip]
		d.ipToChMutex.RUnlock()
		if !ok {
			releaseBuffer(buf)
			glog.Warningf("Unknown destination of packet: %s", dstip)
			continue
		}

		ch <- buf
	}
}

func (d *TUNIPDialer) Dial(raddr net.Addr) (net.Conn, error) {
	ifname, err := d.tun.Name()
	if err != nil {
		return nil, fmt.Errorf("could not get name of TUN device: %w", err)
	}

	conn := &TUNIPDialerConn{
		tun:         d.tun,
		initialized: make(chan struct{}),
		ipToChMutex: &d.ipToChMutex,
		ipToCh:      d.ipToCh,
	}

	return &TUNIPConn{
		ifname:    ifname,
		closeFunc: func() error { return conn.Close() },
		r:         conn,
		w:         conn,
	}, nil
}

type TUNIPDialerConn struct {
	tun       tun.Device
	writeOnce sync.Once
	closeOnce sync.Once

	ipToChMutex *sync.RWMutex
	ipToCh      map[netip.Addr]chan *PacketBuf

	initialized chan struct{}

	// below are readable after initialized
	firstSrcIP netip.Addr
	readCh     <-chan *PacketBuf
}

func (c *TUNIPDialerConn) Close() error {
	<-c.initialized

	c.closeOnce.Do(func() {
		c.ipToChMutex.Lock()
		ch, ok := c.ipToCh[c.firstSrcIP]
		if ok && ch == c.readCh {
			glog.Infof("closing its own read chan of client %s", c.firstSrcIP)
			delete(c.ipToCh, c.firstSrcIP)
			close(ch)
		}
		c.ipToChMutex.Unlock()
	})

	return nil
}

func (c *TUNIPDialerConn) Read(p []byte, offset int) (int, error) {
	<-c.initialized

	buf, ok := <-c.readCh
	if !ok {
		return 0, io.EOF
	}
	defer releaseBuffer(buf)

	n := copy(p[offset:], buf.PacketBytes())
	return n, nil
}

func (c *TUNIPDialerConn) Write(b []byte, offset int) (int, error) {
	var err error
	c.writeOnce.Do(func() {
		defer close(c.initialized)

		ip := tcpip.IPPacket(b[offset:])
		ip4 := ip.IPv4Packet()
		if ip4 == nil {
			err = fmt.Errorf("IPv6 packet is not supported")
			return
		}

		c.firstSrcIP, _ = netip.AddrFromSlice(ip4.SrcIP())

		readCh := make(chan *PacketBuf)
		c.readCh = readCh

		c.ipToChMutex.Lock()
		ch, ok := c.ipToCh[c.firstSrcIP]
		if ok {
			glog.Infof("closing the remaining read chan of client %s", c.firstSrcIP)
			close(ch)
		}
		c.ipToCh[c.firstSrcIP] = readCh
		c.ipToChMutex.Unlock()
	})
	if err != nil {
		return 0, err
	}

	return c.tun.Write(b, offset)
}

type TUNIPConn struct {
	ifname string

	once      sync.Once
	closeFunc func() error

	r    OffsetReader
	w    OffsetWriter
	wbuf bytes.Buffer
}

func (c *TUNIPConn) Read(p []byte) (int, error) {
	n, err := c.r.Read(p, 4)
	p[2] = 0
	p[3] = 0
	binary.BigEndian.PutUint16(p[:2], uint16(n))
	return 4 + n, err
}

func (c *TUNIPConn) Write(b []byte) (int, error) {
	c.wbuf.Write(b)
	for {
		if c.wbuf.Len() < 4 {
			return len(b), nil
		}

		n := int(binary.BigEndian.Uint16(c.wbuf.Bytes()[:2]))
		if c.wbuf.Len() < 4+n {
			return len(b), nil
		}

		if _, err := c.w.Write(c.wbuf.Next(4+n), 4); err != nil {
			return len(b), err
		}
	}
}

func (c *TUNIPConn) Close() error {
	return c.closeFunc()
}

func (c *TUNIPConn) LocalAddr() net.Addr {
	return &TUNAddr{c.ifname}
}

func (c *TUNIPConn) RemoteAddr() net.Addr {
	return &TUNAddr{c.ifname}
}

func (c *TUNIPConn) SetDeadline(t time.Time) error {
	// panic("not implemented")
	return nil
}

func (c *TUNIPConn) SetReadDeadline(t time.Time) error {
	panic("not implemented")
}

func (c *TUNIPConn) SetWriteDeadline(t time.Time) error {
	panic("not implemented")
}

type TUNAddr struct {
	ifname string
}

func (a *TUNAddr) Network() string {
	return "tun_if"
}

func (a *TUNAddr) String() string {
	if a.ifname == "" {
		return a.Network()
	}
	return a.Network() + ":" + a.ifname
}

type OffsetReader interface {
	Read([]byte, int) (int, error)
}

type OffsetWriter interface {
	Write([]byte, int) (int, error)
}
