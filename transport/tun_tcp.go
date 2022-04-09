package transport

import (
	"fmt"
	"net"
	"os/exec"
	"sync"

	"golang.zx2c4.com/wireguard/tun"

	"github.com/golang/glog"

	"github.com/cirias/tcpproxy/tcpip"
)

type TCPState byte

const (
	TCPEstablished TCPState = iota
	TCPFinWait
	TCPLastAck
)

type TUNTCPListener struct {
	tun            tun.Device
	tunIP          net.IP
	tcpListener    net.Listener
	tcpMidIP       net.IP
	tcpLaddr       *net.TCPAddr
	tcpDaddrsMutex sync.RWMutex
	tcpDaddrs      map[uint16]*net.TCPAddr // tcp src port -> dst address
	tcpConnStates  map[uint16]TCPState
}

func ListenTUNTCP(name, tunAddr, tcpMidAddr, tcpListenAddr string) (*TUNTCPListener, error) {
	tunIP, tunIPNet, err := net.ParseCIDR(tunAddr)
	if err != nil {
		return nil, fmt.Errorf("could not parse tunAddr: %w", err)
	}

	tcpMidIP := net.ParseIP(tcpMidAddr)
	if tcpMidIP == nil {
		return nil, fmt.Errorf("could not parse tcpMidAddr: %w", err)
	}

	if !tunIPNet.Contains(tcpMidIP) {
		return nil, fmt.Errorf("tcpMidAddr is not within range of tunAddr")
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

	tcpListener, err := net.Listen("tcp", tcpListenAddr)
	if err != nil {
		return nil, fmt.Errorf("could not create TCP listener: %w", err)
	}
	tcpLaddr := tcpListener.Addr().(*net.TCPAddr)

	tunRouteTable := fmt.Sprint(tcpLaddr.Port)

	if err := exec.Command("ip", "rule", "add", "not", "fwmark", fmt.Sprint(tcpproxyBypassMark), "table", tunRouteTable).Run(); err != nil {
		return nil, fmt.Errorf("could not set bypass rule: %w", err)
	}

	if err := exec.Command("ip", "route", "add", "default", "via", tunIP.String(), "dev", tunName, "src", tunIP.String(), "table", tunRouteTable).Run(); err != nil {
		return nil, fmt.Errorf("could not set route table for tun device: %w", err)
	}

	l := &TUNTCPListener{
		tcpListener:   tcpListener,
		tun:           dev,
		tunIP:         tunIP,
		tcpMidIP:      tcpMidIP,
		tcpLaddr:      tcpLaddr,
		tcpDaddrs:     make(map[uint16]*net.TCPAddr),
		tcpConnStates: make(map[uint16]TCPState),
	}
	go func() {
		if err := l.mapTCPPackets(); err != nil {
			glog.Fatalln(err)
		}
	}()

	return l, nil
}

func (l *TUNTCPListener) Accept() (Handshaker, error) {
	conn, err := l.tcpListener.Accept()
	if err != nil {
		return nil, fmt.Errorf("could not accept TCP connection: %w", err)
	}

	return &TUNTCPHandshaker{conn, l}, nil
}

func (l *TUNTCPListener) Close() error {
	err1 := l.tun.Close()
	err2 := l.tcpListener.Close()
	if err1 != nil {
		return err1
	}
	return err2
}

func (l *TUNTCPListener) Addr() net.Addr {
	return l.tcpListener.Addr()
}

func (l *TUNTCPListener) tcpDaddr(port uint16) *net.TCPAddr {
	l.tcpDaddrsMutex.RLock()
	defer l.tcpDaddrsMutex.RUnlock()
	return l.tcpDaddrs[port]
}

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

		ip := tcpip.IPPacket(buf[offset : offset+n])
		ip4 := ip.IPv4Packet()
		if ip4 == nil {
			continue
		}
		tcp := ip4.TransportPacket().(tcpip.TCPPacket)
		if tcp == nil {
			continue
		}

		srcIP := ip4.SrcIP()
		dstIP := ip4.DstIP()
		srcPort := tcp.SrcPort()
		dstPort := tcp.DstPort()

		if (srcIP.Equal(l.tunIP) || srcIP.Equal(l.tcpLaddr.IP)) && int(srcPort) == l.tcpLaddr.Port {
			l.tcpDaddrsMutex.RLock()
			oaddr := l.tcpDaddrs[dstPort]
			l.tcpDaddrsMutex.RUnlock()
			if oaddr == nil {
				continue
			}

			ip4.SetSrcIP(oaddr.IP)
			tcp.SetSrcPort(uint16(oaddr.Port))
			ip4.SetDstIP(l.tunIP)
		} else if srcIP.Equal(l.tunIP) {
			if tcp.SYN() && !tcp.ACK() {
				l.tcpConnStates[srcPort] = TCPEstablished
				dst := make(net.IP, len(dstIP))
				copy(dst, dstIP)
				l.tcpDaddrsMutex.Lock()
				l.tcpDaddrs[srcPort] = &net.TCPAddr{IP: dst, Port: int(dstPort)}
				l.tcpDaddrsMutex.Unlock()
			}

			ip4.SetSrcIP(l.tcpMidIP)
			ip4.SetDstIP(l.tcpLaddr.IP)
			tcp.SetDstPort(uint16(l.tcpLaddr.Port))
		}

		if tcp.RST() || tcp.ACK() && l.tcpConnStates[srcPort] == TCPLastAck {
			l.tcpDaddrsMutex.Lock()
			delete(l.tcpDaddrs, srcPort)
			l.tcpDaddrsMutex.Unlock()

			delete(l.tcpConnStates, srcPort)
		} else if tcp.FIN() {
			// FIXME check packet direction
			switch l.tcpConnStates[srcPort] {
			case TCPEstablished:
				l.tcpConnStates[srcPort] = TCPFinWait
			case TCPFinWait:
				l.tcpConnStates[srcPort] = TCPLastAck
			}
		}

		ip4.UpdateChecksum()
		tcp.UpdateChecksum(ip4)

		if _, err := l.tun.Write(buf[:offset+n], offset); err != nil {
			return err
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
