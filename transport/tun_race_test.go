package transport

import (
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	wgtun "golang.zx2c4.com/wireguard/tun"
)

type fakeTUN struct {
	readCh   chan []byte
	eventsCh chan wgtun.Event
	closedCh chan struct{}
	closeOnce sync.Once
}

func newFakeTUN() *fakeTUN {
	return &fakeTUN{
		readCh:   make(chan []byte, 1),
		eventsCh: make(chan wgtun.Event, 1),
		closedCh: make(chan struct{}),
	}
}

func (t *fakeTUN) File() *os.File {
	return nil
}

func (t *fakeTUN) Read(b []byte, offset int) (int, error) {
	select {
	case <-t.closedCh:
		return 0, io.EOF
	case pkt, ok := <-t.readCh:
		if !ok {
			return 0, io.EOF
		}
		copy(b[offset:], pkt)
		return len(pkt), nil
	}
}

func (t *fakeTUN) Write(b []byte, offset int) (int, error) {
	return len(b) - offset, nil
}

func (t *fakeTUN) Flush() error {
	return nil
}

func (t *fakeTUN) MTU() (int, error) {
	return 1500, nil
}

func (t *fakeTUN) Name() (string, error) {
	return "fake0", nil
}

func (t *fakeTUN) Events() chan wgtun.Event {
	return t.eventsCh
}

func (t *fakeTUN) Close() error {
	t.closeOnce.Do(func() {
		close(t.closedCh)
		close(t.readCh)
		close(t.eventsCh)
	})
	return nil
}

func makeIPv4Packet(dst net.IP) []byte {
	pkt := make([]byte, 20)
	pkt[0] = 0x45 // IPv4, IHL=5
	pkt[9] = 0x11 // UDP protocol (not required by test)
	copy(pkt[12:16], net.IPv4(192, 0, 2, 10).To4())
	copy(pkt[16:20], dst.To4())
	return pkt
}

func TestTUNIPDialer_ReadPacketsRoutine_PanicOnClosedChannel(t *testing.T) {
	tun := newFakeTUN()
	t.Cleanup(func() {
		_ = tun.Close()
	})

	dialer := NewTUNIPDialer(tun)
	dstIP := net.IPv4(203, 0, 113, 1).To4()
	if dstIP == nil {
		t.Fatal("failed to build IPv4 destination")
	}
	dstAddr, ok := netip.AddrFromSlice(dstIP)
	if !ok {
		t.Fatalf("failed to convert dst IP: %v", dstIP)
	}

	readCh := make(chan *PacketBuf)

	// Hold the write lock so the read routine blocks on RLock.
	dialer.ipToChMutex.Lock()
	dialer.ipToCh[dstAddr] = readCh

	panicCh := make(chan interface{}, 1)
	doneCh := make(chan struct{})
	go func() {
		defer func() {
			if r := recover(); r != nil {
				panicCh <- r
			}
			close(doneCh)
		}()
		_ = dialer.ReadPacketsRoutine(context.Background())
	}()

	// Provide a packet and close the channel while the read routine is blocked.
	tun.readCh <- makeIPv4Packet(dstIP)
	close(readCh)
	dialer.ipToChMutex.Unlock()

	select {
	case <-doneCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for panic")
	}

	select {
	case <-panicCh:
	default:
		t.Fatal("expected panic from send on closed channel")
	}
}
