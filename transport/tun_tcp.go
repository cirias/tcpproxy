package transport

import (
  "encoding/binary"
	"fmt"
	"net"
	"os/exec"
	"sync"

	"golang.zx2c4.com/wireguard/tun"

	"github.com/golang/glog"
)

type TCPState byte

const (
	TCPEstablished TCPState = iota
	TCPFinWait
	TCPLastAck
)

type TUNTCPListener struct {
	listener          net.Listener
	tun               tun.Device
	tunIP             net.IP
	fakeIP            net.IP
	laddr             *net.TCPAddr
	originalDstsMutex sync.RWMutex
	originalDsts      map[uint16]*net.TCPAddr // original port -> original destination(ip + port)
	connStates        map[uint16]TCPState
}

func ListenTUNTCP(name, tunAddr, fakeAddr, listenAddr string) (*TUNTCPListener, error) {
	tunIP, tunIPNet, err := net.ParseCIDR(tunAddr)
	if err != nil {
		return nil, fmt.Errorf("could not parse tunAddr: %w", err)
	}

	fakeIP := net.ParseIP(fakeAddr)
	if fakeIP == nil {
		return nil, fmt.Errorf("could not parse fakeAddr: %w", err)
	}

  if !tunIPNet.Contains(fakeIP) {
		return nil, fmt.Errorf("fakeAddr is not within range of tunAddr")
  }

	dev, err := tun.CreateTUN(name, 1420)
	if err != nil {
		return nil, fmt.Errorf("could not create TUN device: %w", err)
	}

	tunName, err := dev.Name()
	if err != nil {
		return nil, fmt.Errorf("could not get TUN device name: %w", err)
	}

	if err := exec.Command("ip", "address", "add", tunAddr, "dev", tunName).Run(); err != nil {
		return nil, fmt.Errorf("could not add IP %s to %s: %w", tunAddr, tunName, err)
	}

  if err := exec.Command("ip", "link", "set", "dev", tunName, "up").Run(); err != nil {
    return nil, fmt.Errorf("could not set %s up: %w", tunName, err)
  }

	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("could not create TCP listener: %w", err)
	}
	laddr := listener.Addr().(*net.TCPAddr)

  tunRouteTable := fmt.Sprint(laddr.Port)

  if err := exec.Command("ip", "rule", "add", "not", "fwmark", fmt.Sprint(tcpproxyBypassMark), "table", tunRouteTable).Run(); err != nil {
    return nil, fmt.Errorf("could not set bypass rule: %w", err)
  }

  if err := exec.Command("ip", "route", "add", "default", "via", tunIP.String(), "dev", tunName, "src", tunIP.String(), "table", tunRouteTable).Run(); err != nil {
    return nil, fmt.Errorf("could not set route table for tun device: %w", err)
  }

  l := &TUNTCPListener{
		listener:     listener,
		tun:          dev,
		tunIP:        tunIP,
		fakeIP:       fakeIP,
		laddr:        laddr,
		originalDsts: make(map[uint16]*net.TCPAddr),
		connStates:   make(map[uint16]TCPState),
	}
  go func() {
    if err := l.mapTCPPackets(); err != nil {
      glog.Fatalln(err)
    }
  }()

  return l, nil
}

func (l *TUNTCPListener) Accept() (Handshaker, error) {
	conn, err := l.listener.Accept()
	if err != nil {
		return nil, fmt.Errorf("could not accept TCP connection: %w", err)
	}

	return &TUNTCPHandshaker{conn, l}, nil
}

func (l *TUNTCPListener) Close() error {
	err1 := l.tun.Close()
	err2 := l.listener.Close()
	if err1 != nil {
		return err1
	}
	return err2
}

func (l *TUNTCPListener) Addr() net.Addr {
	return l.listener.Addr()
}

type TUNTCPHandshaker struct {
	net.Conn
	listener *TUNTCPListener
}

func (h *TUNTCPHandshaker) Handshake() (conn net.Conn, raddr net.Addr, err error) {
	saddr := h.Conn.RemoteAddr().(*net.TCPAddr)

	addr := h.listener.originalAddr(uint16(saddr.Port))
	if addr == nil {
		return nil, nil, fmt.Errorf("no original address found for port %d", saddr.Port)
	}
	return h.Conn, addr, nil
}

var emptyHardwareAddr = net.HardwareAddr{0,0,0,0,0,0}

/*
 * Tun Device Address: 192.168.200.1/24
 * TCP Server Address: 127.0.0.1:12345
 *
 * |--------| 192.168.200.1:56789 -> 1.1.1.1:443 |-----| 192.168.200.2:56789 -> 127.0.0.1:12345     |------------|
 * | Client |                                    | Tun |                                            | TCP Server |
 * |--------| 192.168.200.1:56789 <- 1.1.1.1:443 |-----| 192.168.200.2:56789 <- 192.168.200.1:12345 |------------|
 */

func (l *TUNTCPListener) mapTCPPackets() error {
	buf := make([]byte, 4096)
  offset := 4
	for {
		n, err := l.tun.Read(buf, offset)
		if err != nil {
			return err
		}

    ip := IPPacket(buf[offset:offset+n])
    ip4 := ip.IPv4Packet()
    if ip4 == nil {
      continue
    }
    tcp := ip4.TCPPacket()
    if tcp == nil {
      continue
    }

    srcIP := ip4.SrcIP()
    dstIP := ip4.DstIP()
    srcPort := tcp.SrcPort()
    dstPort := tcp.DstPort()

    if (srcIP.Equal(l.tunIP) || srcIP.Equal(l.laddr.IP)) && int(srcPort) == l.laddr.Port {
      l.originalDstsMutex.RLock()
      oaddr := l.originalDsts[dstPort]
      l.originalDstsMutex.RUnlock()
      if oaddr == nil {
        continue
      }
 
      ip4.SetSrcIP(oaddr.IP)
      tcp.SetSrcPort(uint16(oaddr.Port))
      ip4.SetDstIP(l.tunIP)
    } else if srcIP.Equal(l.tunIP) {
    if tcp.SYN() && !tcp.ACK() {
      l.connStates[srcPort] = TCPEstablished
      dst := make(net.IP, len(dstIP))
      copy(dst, dstIP)
      l.originalDstsMutex.Lock()
      l.originalDsts[srcPort] = &net.TCPAddr{IP: dst, Port: int(dstPort)}
      l.originalDstsMutex.Unlock()
    }
 
      ip4.SetSrcIP(l.fakeIP)
      ip4.SetDstIP(l.laddr.IP)
      tcp.SetDstPort(uint16(l.laddr.Port))
    }
 
    if tcp.RST() || tcp.ACK() && l.connStates[srcPort] == TCPLastAck {
      delete(l.connStates, srcPort)
      l.originalDstsMutex.Lock()
      delete(l.originalDsts, srcPort)
      l.originalDstsMutex.Unlock()
    } else if tcp.FIN() {
      switch l.connStates[srcPort] {
      case TCPEstablished:
        l.connStates[srcPort] = TCPFinWait
      case TCPFinWait:
        l.connStates[srcPort] = TCPLastAck
      }
    }

    ip4.UpdateChecksum()
    tcp.UpdateChecksum(ip4)

    if _, err := l.tun.Write(buf[:offset+n], offset); err != nil {
      return err
    }
	}
}

func (l *TUNTCPListener) originalAddr(port uint16) *net.TCPAddr {
	l.originalDstsMutex.RLock()
	defer l.originalDstsMutex.RUnlock()
	return l.originalDsts[port]
}

const (
  IPv4SrcOffset      = 12
  IPv4DstOffset      = IPv4SrcOffset + net.IPv4len
  IPv4ProtocolOffset = 9

  ProtocolTCP = 0x06
)

type IPPacket []byte

func (p IPPacket) Version() byte {
  version := p[0] >> 4
  return version
}

func (p IPPacket) IPv4Packet() IPv4Packet {
  if (p.Version() != 4){
 return nil
  }
  return IPv4Packet(p)
}

type IPv4Packet []byte

func (p IPv4Packet) Protocol() byte {
  return p[IPv4ProtocolOffset]
}

func (p IPv4Packet) HeaderLength() int {
  l := 20
  ihl := p[0] & 0x0f
  if (ihl > 5) {
    l = int(ihl) * 4
  }
  return l
}

func (p IPv4Packet) TCPPacket() TCPPacket {
  if (p.Protocol() != ProtocolTCP) {
    return nil
  }

  return TCPPacket(p[p.HeaderLength():])
}

func (p IPv4Packet) SrcIP() net.IP {
  return net.IP(p[IPv4SrcOffset : IPv4SrcOffset+net.IPv4len])
}

func (p IPv4Packet) SetSrcIP(ip net.IP) {
  copy(p[IPv4SrcOffset:IPv4SrcOffset+net.IPv4len], ip.To4())
}

func (p IPv4Packet) DstIP() net.IP {
  return net.IP(p[IPv4DstOffset : IPv4DstOffset+net.IPv4len])
}

func (p IPv4Packet) SetDstIP(ip net.IP) {
  copy(p[IPv4DstOffset:IPv4DstOffset+net.IPv4len], ip.To4())
}

func (p IPv4Packet) UpdateChecksum() {
	p[10] = 0
	p[11] = 0
  binary.BigEndian.PutUint16(p[10:], tcpipChecksum(p[:p.HeaderLength()], 0))
}

func (p IPv4Packet) pseudoheaderChecksum() (csum uint32) {
	csum += (uint32(p.SrcIP()[0]) + uint32(p.SrcIP()[2])) << 8
	csum += uint32(p.SrcIP()[1]) + uint32(p.SrcIP()[3])
	csum += (uint32(p.DstIP()[0]) + uint32(p.DstIP()[2])) << 8
	csum += uint32(p.DstIP()[1]) + uint32(p.DstIP()[3])
	return csum
}

type TCPPacket []byte

func (p TCPPacket) SrcPort() uint16 {
  return uint16(p[0])<<8 + uint16(p[1])
}

func (p TCPPacket) SetSrcPort(port uint16) {
  binary.BigEndian.PutUint16(p[0:], port)
}

func (p TCPPacket) DstPort() uint16 {
  return uint16(p[2])<<8 + uint16(p[3])
}

func (p TCPPacket) SetDstPort(port uint16) {
  binary.BigEndian.PutUint16(p[2:], port)
}

func (p TCPPacket) FIN() bool {
	return p[13]&0x01 != 0
}

func (p TCPPacket) SYN() bool {
	return p[13]&0x02 != 0
}

func (p TCPPacket) RST() bool {
	return p[13]&0x04 != 0
}

func (p TCPPacket) ACK() bool {
	return p[13]&0x10 != 0
}

func (p TCPPacket) UpdateChecksum(ip IPv4Packet) {
  p[16] = 0
  p[17] = 0

  csum := ip.pseudoheaderChecksum()
	length := uint32(len(p))
	csum += uint32(ProtocolTCP)
	csum += length & 0xffff
	csum += length >> 16
  binary.BigEndian.PutUint16(p[16:], tcpipChecksum(p, csum))
}

// Calculate the TCP/IP checksum defined in rfc1071.  The passed-in csum is any
// initial checksum data that's already been computed.
func tcpipChecksum(data []byte, csum uint32) uint16 {
	// to handle odd lengths, we loop to length - 1, incrementing by 2, then
	// handle the last byte specifically by checking against the original
	// length.
	length := len(data) - 1
	for i := 0; i < length; i += 2 {
		// For our test packet, doing this manually is about 25% faster
		// (740 ns vs. 1000ns) than doing it by calling binary.BigEndian.Uint16.
		csum += uint32(data[i]) << 8
		csum += uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		csum += uint32(data[length]) << 8
	}
	for csum > 0xffff {
		csum = (csum >> 16) + (csum & 0xffff)
	}
	return ^uint16(csum)
}
