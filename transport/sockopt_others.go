//go:build !linux
// +build !linux

package transport

import (
	"fmt"
	"net"
)

func GetOriginalDestination(conn net.Conn) (*net.TCPAddr, error) {
	return nil, fmt.Errorf("GetOriginalDestination not implemented on this platform")
}

func SetSocketMark(fd int, mark int) error {
	return nil
}
