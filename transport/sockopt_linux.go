//go:build linux
// +build linux

package transport

import (
	"fmt"
	"log"
	"net"
	"syscall"
)

const SO_ORIGINAL_DST = 80

func GetOriginalDestination(conn net.Conn) (*net.TCPAddr, error) {
	syscallConn, ok := conn.(syscall.Conn)
	if !ok {
		return nil, fmt.Errorf("could not get syscall.Conn from net.Conn")
	}

	rawConn, err := syscallConn.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("could not get syscall.RawConn: %w", err)
	}

	var dest *net.TCPAddr
	err = rawConn.Control(func(fd uintptr) {
		addr, err := syscall.GetsockoptIPv6Mreq(int(fd), syscall.IPPROTO_IP, SO_ORIGINAL_DST)
		if err != nil {
			log.Println(fmt.Errorf("could not call getsockopt SO_ORIGINAL_DST: %w", err))
			return
		}

		dest = &net.TCPAddr{
			IP:   addr.Multiaddr[4:8],
			Port: int(addr.Multiaddr[2])<<8 + int(addr.Multiaddr[3]),
		}
	})
	if err != nil {
		return nil, fmt.Errorf("could not run control on rawConn: %w", err)
	}

	return dest, nil
}

func SetSocketMark(fd int, mark int) error {
	return syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_MARK, mark)
}
