package tcpip

import (
	"encoding/binary"
	"net"
)

const (
	IPv4SrcOffset      = 12
	IPv4DstOffset      = IPv4SrcOffset + net.IPv4len
	IPv4ProtocolOffset = 9

	ProtocolTCP = 0x06
	ProtocolUDP = 0x11

	UDPHeaderLen = 8
)

type IPPacket []byte

func (p IPPacket) Version() byte {
	version := p[0] >> 4
	return version
}

func (p IPPacket) IPv4Packet() IPv4Packet {
	if p.Version() != 4 {
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
	if ihl > 5 {
		l = int(ihl) * 4
	}
	return l
}

func (p IPv4Packet) TransportPacket() interface{} {
	transport := p[p.HeaderLength():]
	switch p.Protocol() {
	case ProtocolTCP:
		return TCPPacket(transport)
	case ProtocolUDP:
		return UDPPacket(transport)
	default:
		return nil
	}
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

func (p TCPPacket) SeqNum() int {
	return int(p[4])<<24 + int(p[5])<<16 + int(p[6])<<8 + int(p[7])
}

func (p TCPPacket) ACKNum() int {
	return int(p[8])<<24 + int(p[9])<<16 + int(p[10])<<8 + int(p[11])
}

func (p TCPPacket) UpdateChecksum(ip IPv4Packet) {
	p[16] = 0
	p[17] = 0

	csum := ip.pseudoheaderChecksum()

	csum += uint32(ProtocolTCP)
	length := uint32(len(p))

	csum += length & 0xffff
	csum += length >> 16
	binary.BigEndian.PutUint16(p[16:], tcpipChecksum(p, csum))
}

type UDPPacket []byte

func (p UDPPacket) SrcPort() uint16 {
	return uint16(p[0])<<8 + uint16(p[1])
}

func (p UDPPacket) DstPort() uint16 {
	return uint16(p[2])<<8 + uint16(p[3])
}

func (p UDPPacket) Payload() []byte {
	return p[UDPHeaderLen:]
}

/*
* 0x0000:  4500 0053 74a5 4000 3f11 9089 0a0a 804d
* 0x0010:  ac11 0003 0035 ab0d 003f f1ce 4296 8180
* 0x0020:  0001 0001 0000 0001 0667 6f6f 676c 6503
* 0x0030:  636f 6d00 0001 0001 c00c 0001 0001 0000
* 0x0040:  0120 0004 d83a c2ae 0000 2904 d000 0000
* 0x0050:  0000 00
 */
var defaultIPv4Header []byte = []byte{
	0x45,       // Version, IHL
	0x00,       // DSCP, ECN
	0x00, 0x00, // Total Length
	0x00, 0x00, // Identification
	0x40, 0x00, // Flag, Fragment Offset
	0x3f, 0x11, // TTL, Protocol
	0x00, 0x00, // Head Checksum
}

func NewUDPPacket(buf []byte, src, dst net.IP, srcPort, dstPort uint16, payload []byte) int {
	if len(src) != 4 || len(dst) != 4 {
		// only ipv4 is supported
		return 0
	}

	buf[20] = byte(srcPort >> 8)
	buf[21] = byte(srcPort)
	buf[22] = byte(dstPort >> 8)
	buf[23] = byte(dstPort)
	udpLength := 8 + len(payload)
	buf[24] = byte(udpLength >> 8)
	buf[25] = byte(udpLength)

	copy(buf, defaultIPv4Header)
  ip4 := IPv4Packet(buf)
  ipLen := 20 + udpLength
  buf[2] = byte(ipLen >> 8)
  buf[3] = byte(ipLen)
  ip4.SetSrcIP(src)
  ip4.SetDstIP(dst)
  ip4.UpdateChecksum()

  // UDP checksum is optional for IPv4
	buf[26] = 0
	buf[27] = 0
	copy(buf[28:], payload)
	return 28+len(payload)
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
