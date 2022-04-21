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

type TCPConnState struct {
	srcip [4]byte
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
	name     string
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

	glog.Infof("created TUN device %s at %s", tunName, tunIP)

	return &TUN{
		name:     tunName,
		tun:      tun,
		tunIP:    tunIP,
		tunIPNet: tunIPNet,
	}, nil
}

func (t *TUN) EnableDefaultRoute() error {
	// ugly way to clean the previous created rules
	for {
		if err := exec.Command("ip", "rule", "del", "not", "fwmark", fmt.Sprint(tcpproxyBypassMark), "table", tunRouteTable).Run(); err != nil {
			break
		}
	}
	if err := exec.Command("ip", "rule", "add", "not", "fwmark", fmt.Sprint(tcpproxyBypassMark), "table", tunRouteTable).Run(); err != nil {
		return fmt.Errorf("could not set bypass rule: %w", err)
	}

	for {
		if err := exec.Command("ip", "rule", "del", "lookup", "main", "suppress_prefixlength", "0").Run(); err != nil {
			break
		}
	}
	if err := exec.Command("ip", "rule", "add", "lookup", "main", "suppress_prefixlength", "0").Run(); err != nil {
		return fmt.Errorf("could not set bypass rule: %w", err)
	}

	if err := exec.Command("ip", "route", "add", "table", tunRouteTable, "default", "dev", t.name, "scope", "link").Run(); err != nil {
		return fmt.Errorf("could not set route table for tun device: %w", err)
	}

	glog.Infof("enabled default route to %s", t.name)

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
	var proxyIP [4]byte
	var proxyIPNet *net.IPNet
	if paddr == "" {
		ones, bits := t.tunIPNet.Mask.Size()
		if ones > 24 {
			return nil, fmt.Errorf("IP mask of TUN cannot be larger than 24 when proxy address not specified")
		}
		copy(proxyIP[:], t.tunIP.To4())
		proxyIP[3] ^= 1 << 7
		m := net.CIDRMask(ones+1, bits)
		proxyIPNet = &net.IPNet{
			IP:   net.IP(proxyIP[:]).Mask(m),
			Mask: m,
		}
	} else {
		var err error
		var ip net.IP
		ip, proxyIPNet, err = net.ParseCIDR(paddr)
		if err != nil {
			return nil, fmt.Errorf("could not parse paddr: %w", err)
		}
		if !t.tunIPNet.Contains(ip) {
			return nil, fmt.Errorf("paddr is not within range of tunAddr")
		}
		copy(proxyIP[:], ip.To4())
	}

	laddr := &net.TCPAddr{
		IP:   t.tunIP,
		Port: lport,
	}
	listener, err := net.ListenTCP("tcp", laddr)
	if err != nil {
		return nil, fmt.Errorf("could not create TCP listener: %w", err)
	}
	glog.Infof("created TUN TCP listener, proxyIP=%s proxyIPNet=%s laddr=%s", net.IP(proxyIP[:]), proxyIPNet, listener.Addr())

	l := &TUNTCPListener{
		listener: listener,
		tun:      t.tun,
		tunIP:    t.tunIP,

		srcToProxy:   make(map[[4]byte]*[4]byte),
		proxyIP:      proxyIP,
		proxyIPNet:   proxyIPNet,
		proxyToState: make(map[[4]byte]map[uint16]*TCPConnState),

		proxyToDst: make(map[[4]byte]map[uint16]*net.TCPAddr),

		pktCh: make(chan *PacketBuf, 0),
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

	listener net.Listener

	srcToProxy   map[[4]byte]*[4]byte
	proxyIP      [4]byte
	proxyIPNet   *net.IPNet
	proxyToState map[[4]byte]map[uint16]*TCPConnState

	// src ip -> (src port -> dst address)
	proxyToDst      map[[4]byte]map[uint16]*net.TCPAddr
	proxyToDstMutex sync.RWMutex

	pktCh chan *PacketBuf
}

func (l *TUNTCPListener) allocatProxyIP() *[4]byte {
	ones, bits := l.proxyIPNet.Mask.Size()
	size := 1 << (bits - ones)
	for i := 0; i < size; i++ {
		advanceIP(l.proxyIP[:], l.proxyIPNet)
		if l.proxyToState[l.proxyIP] == nil {
			ip := l.proxyIP
			return &ip
		}
	}
	return nil
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
		conn.Close()
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

func (l *TUNTCPListener) tcpDaddr(proxyAddr *net.TCPAddr) *net.TCPAddr {
	l.proxyToDstMutex.RLock()
	defer l.proxyToDstMutex.RUnlock()

	portToDst := l.proxyToDst[getIP4Array(proxyAddr.IP)]
	if portToDst == nil {
		return nil
	}
	return portToDst[uint16(proxyAddr.Port)]
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

		dstip := getIP4Array(dstIP)

		var oaddr *net.TCPAddr
		{
			l.proxyToDstMutex.RLock()
			portToDst := l.proxyToDst[dstip]
			if portToDst != nil {
				oaddr = portToDst[dstPort]
			}
			l.proxyToDstMutex.RUnlock()
		}
		if oaddr == nil {
			return nil
		}

		l.handleTermination(&tcp, dstip, dstPort)

		ip4.SetSrcIP(oaddr.IP)
		tcp.SetSrcPort(uint16(oaddr.Port))
		ip4.SetDstIP(l.tunIP)
	} else if srcIP.Equal(l.tunIP) {
		// translate packets came from kernel TCP stack

		srcip := getIP4Array(srcIP)
		pproxyip := l.srcToProxy[srcip]

		if tcp.SYN() && !tcp.ACK() {
			glog.Infof("initialize connection %s:%d to %s:%d", l.tunIP, srcPort, dstIP, dstPort)

			if pproxyip == nil {
				pproxyip = l.allocatProxyIP()
				if pproxyip == nil {
					return fmt.Errorf("cannot allocate new proxy IP")
				}
				l.srcToProxy[srcip] = pproxyip
				l.proxyToState[*pproxyip] = make(map[uint16]*TCPConnState)
			}
			l.proxyToState[*pproxyip][srcPort] = &TCPConnState{srcip, TCPSynSent, 0}

			dst := make(net.IP, len(dstIP))
			copy(dst, dstIP)
			{
				l.proxyToDstMutex.Lock()
				portToDst := l.proxyToDst[*pproxyip]
				if portToDst == nil {
					portToDst = make(map[uint16]*net.TCPAddr)
					l.proxyToDst[*pproxyip] = portToDst
				}
				portToDst[srcPort] = &net.TCPAddr{IP: dst, Port: int(dstPort)}
				l.proxyToDstMutex.Unlock()
			}
		}

		if pproxyip == nil {
			glog.Infof("could not find proxy IP for source %s", srcIP)
			return nil
		}

		l.handleTermination(&tcp, *pproxyip, srcPort)

		ip4.SetSrcIP(pproxyip[:])
		ip4.SetDstIP(laddr.IP)
		tcp.SetDstPort(uint16(laddr.Port))
	}

	ip4.UpdateChecksum()
	tcp.UpdateChecksum(ip4)

	_, err := buf.WriteTo(l.tun)
	return err
}

func (l *TUNTCPListener) handleTermination(tcp *tcpip.TCPPacket, proxyip [4]byte, port uint16) {
	portToState := l.proxyToState[proxyip]
	if portToState == nil {
		return
	}
	s := portToState[port]
	if s == nil {
		return
	}

	if tcp.RST() || tcp.ACK() && s.state == TCPLastAck && tcp.ACKNum() == s.seq+1 {
		glog.Infof("terminate connection from %s:%d", l.tunIP, port)
		{
			l.proxyToDstMutex.Lock()
			portToDst := l.proxyToDst[proxyip]
			delete(portToDst, port)
			if len(portToDst) == 0 {
				delete(l.proxyToDst, proxyip)
			}
			l.proxyToDstMutex.Unlock()
		}

		delete(l.proxyToState[proxyip], port)
		if len(l.proxyToState[proxyip]) == 0 {
			delete(l.proxyToState, proxyip)
			delete(l.srcToProxy, s.srcip)
		}
	} else if tcp.FIN() {
		glog.V(1).Infof("FIN of %s:%d", net.IP(proxyip[:]), port)

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

	addr := h.listener.tcpDaddr(saddr)
	if addr == nil {
		h.Conn.Close()
		return nil, nil, fmt.Errorf("no original address found for port %d", saddr.Port)
	}
	return h.Conn, addr, nil
}

func (t *TUN) NewIPListener() *TUNIPListener {
	glog.Infof("created TUN IP listener on %s", t.name)
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

func (l *TUNIPListener) Addr() net.Addr {
	return &TUNAddr{}
}

func (l *TUNIPListener) Accept() (Handshaker, error) {
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

func (t *TUN) NewIPDialer() *TUNIPDialer {
	glog.Infof("created TUN IP dialer on %s", t.name)
	d := &TUNIPDialer{
		tun:    t.tun,
		ipToCh: make(map[[4]byte]chan *PacketBuf),
	}

	go func() {
		for {
			buf := allocateBuffer()
			if _, err := buf.ReadFrom(d.tun); err != nil {
				glog.Fatalln("could not read from TUN device:", err)
				return
			}

			ip := tcpip.IPPacket(buf.PacketBytes())
			ip4 := ip.IPv4Packet()
			if ip4 == nil {
				releaseBuffer(buf)
				glog.Warningf("received IPv6 packet from TUN device")
				continue
			}

			dstip := getIP4Array(ip4.DstIP())

			d.ipToChMutex.RLock()
			ch, ok := d.ipToCh[dstip]
			d.ipToChMutex.RUnlock()
			if !ok {
				releaseBuffer(buf)
				glog.Warningf("Unknown destination of packet: %s", net.IP(dstip[:]))
				continue
			}

			ch <- buf
		}
	}()

	return d
}

type TUNIPDialer struct {
	tun tun.Device

	ipToChMutex sync.RWMutex
	ipToCh      map[[4]byte]chan *PacketBuf
}

func (d *TUNIPDialer) Dial(raddr net.Addr) (net.Conn, error) {

	conn := &TUNIPDialerConn{
		tun:         d.tun,
		initialized: make(chan struct{}),
		ipToChMutex: &d.ipToChMutex,
		ipToCh:      d.ipToCh,
	}

	return &TUNIPConn{
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
	ipToCh      map[[4]byte]chan *PacketBuf

	initialized chan struct{}

	// below are readable after initialized
	firstSrcIP [4]byte
	readCh     <-chan *PacketBuf
}

func (c *TUNIPDialerConn) Close() error {
	<-c.initialized

	c.closeOnce.Do(func() {
		c.ipToChMutex.Lock()
		ch, ok := c.ipToCh[c.firstSrcIP]
		if ok && ch == c.readCh {
			glog.Infof("closing its own read chan of client %s", net.IP(c.firstSrcIP[:]))
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

		c.firstSrcIP = getIP4Array(ip4.SrcIP())

		readCh := make(chan *PacketBuf)
		c.readCh = readCh

		c.ipToChMutex.Lock()
		ch, ok := c.ipToCh[c.firstSrcIP]
		if ok {
			glog.Infof("closing the remaining read chan of client %s", net.IP(c.firstSrcIP[:]))
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
	return tunLocalAddr
}

func (c *TUNIPConn) RemoteAddr() net.Addr {
	return tunRemoteAddr
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

func getIP4Array(ip net.IP) [4]byte {
	ip4 := ip.To4()
	return [4]byte{ip4[0], ip4[1], ip4[2], ip4[3]}
}

func getIP4PortArray(ip net.IP, port uint16) [6]byte {
	ip4 := ip.To4()
	return [6]byte{ip4[0], ip4[1], ip4[2], ip4[3], byte(port >> 8), byte(port)}
}
