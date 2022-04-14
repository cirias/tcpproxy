package transport

import (
	"sync"

	"golang.zx2c4.com/wireguard/tun"
)

var bufferPool = &sync.Pool{
	New: func() interface{} {
		return &PacketBuf{
			buf:    make([]byte, 2048),
			offset: 4,
			n:      0,
		}
	},
}

func allocateBuffer() *PacketBuf {
	return bufferPool.Get().(*PacketBuf)
}

func releaseBuffer(pb *PacketBuf) {
	bufferPool.Put(pb)
}

type PacketBuf struct {
	buf    []byte
	offset int
	n      int
}

func (pb *PacketBuf) ReadFrom(tun tun.Device) (int, error) {
	n, err := tun.Read(pb.buf, pb.offset)
	pb.n = n
	return n, err
}

func (pb *PacketBuf) WriteTo(tun tun.Device) (int, error) {
  n, err := tun.Write(pb.buf[:pb.offset+pb.n], pb.offset)
	return n, err
}

func (pb *PacketBuf) PacketBytes() []byte {
	return pb.buf[pb.offset:pb.offset+pb.n]
}
