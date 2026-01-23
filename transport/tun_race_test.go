package transport

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

// mockTun implements tun.Device for testing
type mockTun struct {
	readCh  chan []byte
	writeCh chan []byte
	events  chan tun.Event
	closed  chan struct{}
}

func newMockTun() *mockTun {
	return &mockTun{
		readCh:  make(chan []byte, 100),
		writeCh: make(chan []byte, 100),
		events:  make(chan tun.Event, 1),
		closed:  make(chan struct{}),
	}
}

func (m *mockTun) File() *os.File { return nil } // Not used in this test path

// Note: Signature matches golang.zx2c4.com/wireguard/tun/tun_linux.go (or common interface)
// Read([]byte, int) (int, error)
func (m *mockTun) Read(buf []byte, offset int) (int, error) {
	select {
	case pkt, ok := <-m.readCh:
		if !ok {
			return 0, io.EOF
		}
		// Check buffer size
		if len(buf) < offset+len(pkt) {
			return 0, io.ErrShortBuffer
		}
		n := copy(buf[offset:], pkt)
		return n, nil
	case <-m.closed:
		return 0, io.EOF
	}
}

// Write([]byte, int) (int, error)
func (m *mockTun) Write(buf []byte, offset int) (int, error) {
	pkt := make([]byte, len(buf)-offset)
	copy(pkt, buf[offset:])
	select {
	case m.writeCh <- pkt:
		return len(pkt), nil
	case <-m.closed:
		return 0, io.EOF
	}
}

func (m *mockTun) Flush() error           { return nil }
func (m *mockTun) MTU() (int, error)      { return 1420, nil }
func (m *mockTun) Name() (string, error)  { return "mocktun", nil }
func (m *mockTun) Events() chan tun.Event { return m.events }
func (m *mockTun) Close() error {
	close(m.closed)
	return nil
}
func (m *mockTun) BatchSize() int { return 1 }

// Helper to create a dummy IPv4 packet
func createIPv4Packet(src, dst net.IP, payload []byte) []byte {
	// Minimal IPv4 header is 20 bytes
	totalLen := 20 + len(payload)
	hdr := make([]byte, 20)
	hdr[0] = 0x45 // Version 4, IHL 5
	hdr[1] = 0    // TOS
	binary.BigEndian.PutUint16(hdr[2:], uint16(totalLen))
	hdr[8] = 64 // TTL
	hdr[9] = 6  // Protocol TCP (doesn't matter for routing logic)
	// Checksum ignored by basic logic usually
	copy(hdr[12:16], src.To4())
	copy(hdr[16:20], dst.To4())

	return append(hdr, payload...)
}

func TestTUNIPDialer_RaceAndDeadlock(t *testing.T) {
	mt := newMockTun()
	dialer := NewTUNIPDialer(mt)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start the packet reading routine
	go func() {
		if err := dialer.ReadPacketsRoutine(ctx); err != nil {
			t.Logf("ReadPacketsRoutine finished: %v", err)
		}
	}()

	clientIP := net.ParseIP("192.168.1.10")
	serverIP := net.ParseIP("10.0.0.1")

	// 1. Establish a connection
	conn, err := dialer.Dial(&net.TCPAddr{IP: clientIP, Port: 1234})
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}

	// Trigger the "addConn" logic by writing a packet OUT to the TUN
	// The dialer expects to see a packet FROM the server TO the client to map the connection?
	// Wait, TUNIPDialer.Write() calls addConn.
	// When we Dial, we get a conn. When we conn.Write(), it sends to TUN.
	// But `addConn` is called inside `conn.Write`.
	// So we must write something to initialize the mapping.

	// Create a packet representing traffic FROM the client (inside app) TO the tunnel interface
	// Src=192.168.1.10 (Client), Dst=...
	packetOut := createIPv4Packet(clientIP, serverIP, []byte("hello"))

	// Add TUNIPConn framing (Length + Reserved)
	framedOut := make([]byte, 4+len(packetOut))
	binary.BigEndian.PutUint16(framedOut[:2], uint16(len(packetOut)))
	copy(framedOut[4:], packetOut)

	_, err = conn.Write(framedOut)
	if err != nil {
		t.Fatalf("conn.Write failed: %v", err)
	}

	// Now the mapping should be established: DST=192.168.1.10 -> conn

	// 2. Verify we can receive packets
	packetIn := createIPv4Packet(serverIP, clientIP, []byte("response"))
	mt.readCh <- packetIn

	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("conn.Read failed: %v", err)
	}
	// Verify payload (offset 4+20 for framing+IP header)
	if string(buf[24:n]) != "response" {
		t.Errorf("Unexpected payload: %s", string(buf[24:n]))
	}

	// 3. Test Race Condition: Close connection concurrently with incoming traffic
	// We will flood packets while closing
	go func() {
		for i := 0; i < 1000; i++ {
			mt.readCh <- createIPv4Packet(serverIP, clientIP, []byte("flood"))
		}
	}()

	time.Sleep(10 * time.Millisecond) // Let some packets flow
	conn.Close()                      // Should not panic

	// 4. Test Deadlock / Blocking
	// Now that conn is closed, packets to 192.168.1.10 should be dropped or ignored.
	// But more importantly, ReadPacketsRoutine should continue processing OTHER traffic.

	// Create a NEW connection for a different IP
	clientIP2 := net.ParseIP("192.168.1.11")
	conn2, _ := dialer.Dial(&net.TCPAddr{IP: clientIP2, Port: 1234})

	// Initialize mapping for conn2
	packetOut2 := createIPv4Packet(clientIP2, serverIP, []byte("init2"))
	framedOut2 := make([]byte, 4+len(packetOut2))
	binary.BigEndian.PutUint16(framedOut2[:2], uint16(len(packetOut2)))
	copy(framedOut2[4:], packetOut2)
	conn2.Write(framedOut2)

	// Send packet to conn2
	packetIn2 := createIPv4Packet(serverIP, clientIP2, []byte("response2"))

	// If ReadPacketsRoutine is deadlocked (e.g. blocked on the closed channel of conn1),
	// this write to readCh will block eventually, or conn2.Read will never return.
	mt.readCh <- packetIn2

	// Actually we expect the next read to be the response
	n, err = conn2.Read(buf)
	if err != nil {
		t.Fatalf("ReadPacketsRoutine seems deadlocked or broken after closing conn1: %v", err)
	}
	if string(buf[24:n]) != "response2" {
		t.Errorf("Unexpected payload for conn2: %s", string(buf[24:n]))
	}
	conn2.Close()
}

func TestTUNIPDialer_BufferOverflow(t *testing.T) {
	mt := newMockTun()
	dialer := NewTUNIPDialer(mt)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { dialer.ReadPacketsRoutine(ctx) }()

	clientIP := net.ParseIP("192.168.1.20")
	serverIP := net.ParseIP("10.0.0.1")

	conn, _ := dialer.Dial(&net.TCPAddr{IP: clientIP})

	packetOut := createIPv4Packet(clientIP, serverIP, []byte("init"))
	framedOut := make([]byte, 4+len(packetOut))
	binary.BigEndian.PutUint16(framedOut[:2], uint16(len(packetOut)))
	copy(framedOut[4:], packetOut)
	conn.Write(framedOut)

	// We do NOT read from conn.
	// We flood > 1024 packets.

	done := make(chan bool)
	go func() {
		for i := 0; i < 1500; i++ {
			mt.readCh <- createIPv4Packet(serverIP, clientIP, []byte("payload"))
		}
		done <- true
	}()

	select {
	case <-done:
		// Success: Producer didn't block forever
	case <-time.After(5 * time.Second):
		t.Fatalf("Deadlock detected! ReadPacketsRoutine blocked when buffer full.")
	}
	conn.Close()
}

// TODO Add test for TUNIPDailer handling multiple connections for the same client IP
