package transport

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
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

func TestTUNIPDialer_MultipleConnsSameIP(t *testing.T) {
	mt := newMockTun()
	dialer := NewTUNIPDialer(mt)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { dialer.ReadPacketsRoutine(ctx) }()

	clientIP := net.ParseIP("192.168.1.30")
	serverIP := net.ParseIP("10.0.0.1")

	// 1. Establish two connections for the same IP
	conn1, _ := dialer.Dial(&net.TCPAddr{IP: clientIP})
	conn2, _ := dialer.Dial(&net.TCPAddr{IP: clientIP})

	// Initialize both mappings to the same clientIP
	packetOut := createIPv4Packet(clientIP, serverIP, []byte("init"))
	framedOut := make([]byte, 4+len(packetOut))
	binary.BigEndian.PutUint16(framedOut[:2], uint16(len(packetOut)))
	copy(framedOut[4:], packetOut)

	conn1.Write(framedOut)
	conn2.Write(framedOut)

	// Channel to receive payloads from both connections
	type pktData struct {
		fromConn int
		payload  string
		err      error
	}
	results := make(chan pktData, 100)

	reader := func(c net.Conn, id int) {
		for {
			buf := make([]byte, 1500)
			n, err := c.Read(buf)
			if err != nil {
				results <- pktData{fromConn: id, err: err}
				return
			}
			results <- pktData{fromConn: id, payload: string(buf[24:n])}
		}
	}

	go reader(conn1, 1)
	go reader(conn2, 2)

	// 2. Send 20 packets. They should be distributed between conn1 and conn2.
	numPackets := 20
	go func() {
		for i := 0; i < numPackets; i++ {
			mt.readCh <- createIPv4Packet(serverIP, clientIP, []byte(fmt.Sprintf("pkt-%d", i)))
		}
	}()

	receivedCount := 0
	timeout := time.After(2 * time.Second)

	// Expect 20 successful packets
	for receivedCount < numPackets {
		select {
		case res := <-results:
			if res.err != nil {
				// conn closed?
				continue
			}
			receivedCount++
		case <-timeout:
			t.Fatalf("Timed out waiting for packets. Got %d/%d", receivedCount, numPackets)
		}
	}

	// 3. Close conn1 and ensure conn2 gets subsequent packets
	conn1.Close()

	// Wait for conn1 closure to propagate (optional, but good for stability)
	// reader(conn1) should return error
	// We might receive an error from conn1 in results channel, ignore it.

	mt.readCh <- createIPv4Packet(serverIP, clientIP, []byte("final"))

	// We expect "final" from conn2 (id=2)
	timeout = time.After(2 * time.Second)
	foundFinal := false

	for !foundFinal {
		select {
		case res := <-results:
			if res.err != nil {
				continue
			}
			if res.payload == "final" {
				if res.fromConn != 2 {
					t.Errorf("Expected 'final' on conn2, got on conn%d", res.fromConn)
				}
				foundFinal = true
			}
		case <-timeout:
			t.Fatalf("Timed out waiting for 'final' packet")
		}
	}

	conn2.Close()
}

func TestTUNIPDialer_ConcurrentClose(t *testing.T) {
	mt := newMockTun()
	dialer := NewTUNIPDialer(mt)

	clientIP := net.ParseIP("192.168.1.10")
	serverIP := net.ParseIP("10.0.0.1")
	conn, err := dialer.Dial(&net.TCPAddr{IP: clientIP})
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}

	// Trigger addConn by writing a packet.
	// This starts a goroutine in the dialer that listens on c.done.
	packetOut := createIPv4Packet(clientIP, serverIP, []byte("hello"))
	framedOut := make([]byte, 4+len(packetOut))
	binary.BigEndian.PutUint16(framedOut[:2], uint16(len(packetOut)))
	copy(framedOut[4:], packetOut)

	if _, err := conn.Write(framedOut); err != nil {
		t.Fatalf("conn.Write failed: %v", err)
	}

	// Call Close concurrently many times.
	// This ensures both the channel closing and the removal from group.conns are safe.
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn.Close()
		}()
	}
	wg.Wait()
}
