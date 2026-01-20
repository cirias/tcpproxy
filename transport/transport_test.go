package transport

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

type mockAddr struct{}

func (mockAddr) Network() string { return "tcp" }
func (mockAddr) String() string  { return "127.0.0.1:0" }

type mockListener struct {
	mu          sync.Mutex
	closed      bool
	acceptCh    chan Handshaker
	closeCalled bool
}

func newMockListener() *mockListener {
	return &mockListener{
		acceptCh: make(chan Handshaker),
	}
}

func (l *mockListener) Accept() (Handshaker, error) {
	h, ok := <-l.acceptCh
	if !ok {
		return nil, errors.New("listener closed")
	}
	return h, nil
}

func (l *mockListener) Addr() net.Addr {
	return mockAddr{}
}

func (l *mockListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.closed {
		l.closed = true
		l.closeCalled = true
		close(l.acceptCh)
	}
	return nil
}

type mockDialer struct {
	dialFunc func(raddr net.Addr) (net.Conn, error)
}

func (d *mockDialer) Dial(raddr net.Addr) (net.Conn, error) {
	if d.dialFunc != nil {
		return d.dialFunc(raddr)
	}
	return nil, errors.New("not implemented")
}

type mockConn struct {
	net.Conn
	readErr   error
	writeErr  error
	closed    bool
	mu        sync.Mutex
	blockRead chan struct{}
}

func (c *mockConn) Read(b []byte) (n int, err error) {
	if c.blockRead != nil {
		<-c.blockRead
	}
	if c.readErr != nil {
		return 0, c.readErr
	}
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return 0, io.EOF
	}
	// Return some data for Write testing
	if len(b) > 0 {
		return copy(b, []byte("data")), nil
	}
	return 0, io.EOF
}

func (c *mockConn) Write(b []byte) (n int, err error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return len(b), nil
}

func (c *mockConn) SetDeadline(t time.Time) error { return nil }
func (c *mockConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.closed = true
		if c.blockRead != nil {
			select {
			case <-c.blockRead:
			default:
				close(c.blockRead)
			}
		}
	}
	return nil
}
func (c *mockConn) RemoteAddr() net.Addr { return mockAddr{} }
func (c *mockConn) LocalAddr() net.Addr  { return mockAddr{} }

type mockHandshaker struct {
	handshakeFunc func() (net.Conn, net.Addr, error)
	remoteAddr    net.Addr
	closed        bool
	mu            sync.Mutex
}

func (h *mockHandshaker) Handshake() (net.Conn, net.Addr, error) {
	if h.handshakeFunc != nil {
		return h.handshakeFunc()
	}
	return nil, nil, errors.New("not implemented")
}

func (h *mockHandshaker) Close() error {
	h.mu.Lock()
	h.closed = true
	h.mu.Unlock()
	return nil
}
func (h *mockHandshaker) RemoteAddr() net.Addr {
	if h.remoteAddr != nil {
		return h.remoteAddr
	}
	return mockAddr{}
}

func TestRoundTripper_Lifecycle(t *testing.T) {
	l := newMockListener()
	rt := &RoundTripper{
		Listeners: []Listener{l},
		Dialer:    &mockDialer{},
	}

	ctx, cancel := context.WithCancel(context.Background())
	
	done := make(chan error)
	go func() {
		done <- rt.RoundTrip(ctx)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("RoundTrip did not exit in time")
	}

	l.mu.Lock()
	if !l.closeCalled {
		t.Error("Listener.Close() was not called")
	}
	l.mu.Unlock()
}

func TestRoundTripper_HandleReadError(t *testing.T) {
	readErr := errors.New("read error")
	inConn := &mockConn{readErr: readErr}
	// outConn will block on read until closed
	outConn := &mockConn{blockRead: make(chan struct{})}

	h := &mockHandshaker{
		handshakeFunc: func() (net.Conn, net.Addr, error) {
			return inConn, mockAddr{}, nil
		},
	}

	l := newMockListener()
	rt := &RoundTripper{
		Listeners: []Listener{l},
		Dialer: &mockDialer{
			dialFunc: func(raddr net.Addr) (net.Conn, error) {
				return outConn, nil
			},
		},
		Timeout: 100 * time.Millisecond,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error)
	go func() {
		done <- rt.RoundTrip(ctx)
	}()

	// Wait for RoundTrip to start
	time.Sleep(50 * time.Millisecond)
	l.acceptCh <- h

	// Wait a bit for processing
	time.Sleep(100 * time.Millisecond)

	// Verify RoundTrip is still running
	select {
	case err := <-done:
		t.Fatalf("RoundTrip exited unexpectedly with error: %v", err)
	default:
		// Good, still running
	}

	// Verify connections and handshaker are closed
	h.mu.Lock()
	if !h.closed {
		t.Error("Handshaker was not closed")
	}
	h.mu.Unlock()

	inConn.mu.Lock()
	if !inConn.closed {
		t.Error("inConn was not closed")
	}
	inConn.mu.Unlock()

	outConn.mu.Lock()
	if !outConn.closed {
		t.Error("outConn was not closed")
	}
	outConn.mu.Unlock()
}

func TestRoundTripper_HandleWriteError(t *testing.T) {
	writeErr := errors.New("write error")
	inConn := &mockConn{} // Will provide data to trigger Write
	// outConn will fail on write, block on read
	outConn := &mockConn{writeErr: writeErr, blockRead: make(chan struct{})}

	h := &mockHandshaker{
		handshakeFunc: func() (net.Conn, net.Addr, error) {
			return inConn, mockAddr{}, nil
		},
	}

	l := newMockListener()
	rt := &RoundTripper{
		Listeners: []Listener{l},
		Dialer: &mockDialer{
			dialFunc: func(raddr net.Addr) (net.Conn, error) {
				return outConn, nil
			},
		},
		Timeout: 100 * time.Millisecond,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error)
	go func() {
		done <- rt.RoundTrip(ctx)
	}()

	// Wait for RoundTrip to start
	time.Sleep(50 * time.Millisecond)
	l.acceptCh <- h

	// Wait a bit for processing
	time.Sleep(100 * time.Millisecond)

	// Verify RoundTrip is still running
	select {
	case err := <-done:
		t.Fatalf("RoundTrip exited unexpectedly with error: %v", err)
	default:
		// Good, still running
	}

	// Verify connections and handshaker are closed
	h.mu.Lock()
	if !h.closed {
		t.Error("Handshaker was not closed")
	}
	h.mu.Unlock()

	inConn.mu.Lock()
	if !inConn.closed {
		t.Error("inConn was not closed")
	}
	inConn.mu.Unlock()

	outConn.mu.Lock()
	if !outConn.closed {
		t.Error("outConn was not closed")
	}
	outConn.mu.Unlock()
}