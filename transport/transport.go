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

type NetDialer interface {
	Dial(network, addr string) (net.Conn, error)
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

type Listener interface {
	Accept() (Answerer, error)
	Addr() net.Addr
	Close() error
}

type Answerer interface {
	Close() error
	Answer() (net.Conn, net.Addr, error)
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
}

type Dialer interface {
	Dial(raddr net.Addr) (net.Conn, error)
}

type RoundTripper struct {
	Listeners []Listener
	Dialer    Dialer
}

func (rt *RoundTripper) RoundTrip(ctx context.Context) error {
	g, ctx := errgroup.WithContext(ctx)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	for _, listener := range rt.Listeners {
		l := listener
		g.Go(func() error {
			// cancel all other listeners
			defer cancel()

			go func() {
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

func (rt *RoundTripper) handle(answerer Answerer) error {
	inConn, raddr, err := answerer.Answer()
	if err != nil {
		return fmt.Errorf("could not handshake [from %s]: %w", answerer.RemoteAddr(), err)
	}

	outConn, err := rt.Dialer.Dial(raddr)
	if err != nil {
		return fmt.Errorf("could not dial: %w", err)
	}
	glog.Infof("connected through proxy [%s <-> %s]", answerer.RemoteAddr(), raddr)
	defer glog.Infof("connection closed [%s <-> %s]", answerer.RemoteAddr(), raddr)

	errOnce := sync.Once{}
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer inConn.Close()
		defer outConn.Close()
		e := copyConn("->", inConn, outConn)
		errOnce.Do(func() {
			err = e
		})
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer inConn.Close()
		defer outConn.Close()
		e := copyConn("<-", outConn, inConn)
		errOnce.Do(func() {
			err = e
		})
	}()

	wg.Wait()

	return err
}

func copyConn(prefix string, i, o net.Conn) error {
	b := make([]byte, 8*1024)
	for {
		if err := i.SetDeadline(time.Now().Add(time.Minute)); err != nil {
			return fmt.Errorf("%s could not set deadline when read from %s: %w", prefix, i.RemoteAddr(), err)
		}
		if glog.V(3) {
			glog.Infof("%s reading from %s", prefix, i.RemoteAddr())
		}
		n, err := i.Read(b)
		if err != nil {
			return fmt.Errorf("%s could not read from %s: %w", prefix, i.RemoteAddr(), err)
		}
		if glog.V(3) {
			glog.Infof("%s read bytes from %s: %d", prefix, i.RemoteAddr(), n)
		}

		if err := o.SetDeadline(time.Now().Add(time.Minute)); err != nil {
			return fmt.Errorf("%s could not set deadline when write to %s: %w", prefix, o.RemoteAddr(), err)
		}
		if glog.V(3) {
			glog.Infof("%s writing to %s", prefix, o.RemoteAddr())
		}
		m, err := o.Write(b[:n])
		if err != nil {
			return fmt.Errorf("%s could not write to %s: %w", prefix, o.RemoteAddr(), err)
		}
		if glog.V(3) {
			glog.Infof("%s written bytes to %s: %d", prefix, o.RemoteAddr(), m)
		}
	}
}
