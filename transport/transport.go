package transport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/golang/glog"
)

var copyBufPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 8*1024)
	},
}

type NetDialer interface {
	Dial(network, addr string) (net.Conn, error)
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

type Listener interface {
	Accept() (Handshaker, error)
	Addr() net.Addr
	Close() error
}

type Handshaker interface {
	Close() error
	Handshake() (net.Conn, net.Addr, error)
	RemoteAddr() net.Addr
}

type Dialer interface {
	Dial(raddr net.Addr) (net.Conn, error)
}

type RoundTripper struct {
	Listeners []Listener
	Dialer    Dialer
	Timeout   time.Duration
}

func (rt *RoundTripper) RoundTrip(ctx context.Context) error {
	g, ctx := errgroup.WithContext(ctx)

	for _, listener := range rt.Listeners {
		l := listener
		g.Go(func() error {
			go func() {
				// ctx will be canceled on the first not nil error returned from the Go func
				<-ctx.Done()
				l.Close()
			}()

			for {
				h, err := l.Accept()
				if err != nil {
					return fmt.Errorf("could not accept connection from listener %s: %w", l.Addr(), err)
				}

				go func() {
					defer h.Close()
					if err := rt.handle(h); err != nil && !errors.Is(err, io.EOF) {
						glog.Errorln(err)
					}
				}()
			}
		})
	}
	return g.Wait()
}

func (rt *RoundTripper) handle(handshaker Handshaker) error {
	glog.Infof("handle handshaker [from %s]", handshaker.RemoteAddr())
	inConn, raddr, err := handshaker.Handshake()
	if err != nil {
		return fmt.Errorf("could not handshake [from %s]: %w", handshaker.RemoteAddr(), err)
	}

	outConn, err := rt.Dialer.Dial(raddr)
	if err != nil {
		return fmt.Errorf("could not dial: %w", err)
	}

	start := time.Now()
	glog.Infof("connected through proxy [%s <-> %s]", handshaker.RemoteAddr(), raddr)

	var tx, rx int64
	defer func() {
		glog.Infof("connection closed [%s <-> %s] duration=%s tx=%d rx=%d", handshaker.RemoteAddr(), raddr, time.Since(start), tx, rx)
	}()

	errOnce := sync.Once{}
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer inConn.Close()
		defer outConn.Close()
		n, e := copyConn("->", inConn, outConn, rt.Timeout)
		tx = n
		errOnce.Do(func() {
			err = e
		})
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer inConn.Close()
		defer outConn.Close()
		n, e := copyConn("<-", outConn, inConn, rt.Timeout)
		rx = n
		errOnce.Do(func() {
			err = e
		})
	}()

	wg.Wait()

	return err
}

func copyConn(prefix string, i, o net.Conn, timeout time.Duration) (int64, error) {
	if timeout == 0 {
		timeout = time.Hour
	}
	var total int64
	b := copyBufPool.Get().([]byte)
	defer copyBufPool.Put(b)

	for {
		if err := i.SetDeadline(time.Now().Add(timeout)); err != nil {
			return total, fmt.Errorf("%s could not set deadline when read from %s: %w", prefix, i.RemoteAddr(), err)
		}
		if glog.V(3) {
			glog.Infof("%s reading from %s", prefix, i.RemoteAddr())
		}
		n, err := i.Read(b)
		if err != nil {
			return total, fmt.Errorf("%s could not read from %s: %w", prefix, i.RemoteAddr(), err)
		}
		if glog.V(3) {
			glog.Infof("%s read bytes from %s: %d", prefix, i.RemoteAddr(), n)
		}

		if err := o.SetDeadline(time.Now().Add(timeout)); err != nil {
			return total, fmt.Errorf("%s could not set deadline when write to %s: %w", prefix, o.RemoteAddr(), err)
		}
		if glog.V(3) {
			glog.Infof("%s writing to %s", prefix, o.RemoteAddr())
		}
		m, err := o.Write(b[:n])
		if err != nil {
			return total, fmt.Errorf("%s could not write to %s: %w", prefix, o.RemoteAddr(), err)
		}
		if glog.V(3) {
			glog.Infof("%s written bytes to %s: %d", prefix, o.RemoteAddr(), m)
		}
		total += int64(m)
	}
}
