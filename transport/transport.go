package transport

import (
	"context"
	"fmt"
	"net"
	// "time"

	"golang.org/x/sync/errgroup"

	"github.com/golang/glog"
)

type NetDialer interface {
	Dial(network, addr string) (net.Conn, error)
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

type Listener interface {
	Accept() (Handshaker, error)
	Close() error
}

type Handshaker interface {
	Handshake() (net.Conn, net.Addr, error)
	RemoteAddr() net.Addr
}

type Dialer interface {
	Dial(raddr net.Addr) (net.Conn, error)
}

type RoundTripper struct {
	Listeners []Listener
	Dialer   Dialer
}

func (rt *RoundTripper) RoundTrip() error {
  g := new(errgroup.Group)
  for _, listener := range rt.Listeners {
    l := listener
    g.Go(func () error {
      defer l.Close()
      for {
        h, err := l.Accept()
        if err != nil {
          glog.Errorln("could not accept:", err)
          continue
        }
        glog.Infof("accepted %s", h.RemoteAddr())

        go func() {
          if err := rt.handle(h); err != nil {
            glog.Errorln(err)
          }
        }()
      }
    })
  }
  return g.Wait()
}

func (rt *RoundTripper) handle(handshaker Handshaker) error {
	inConn, raddr, err := handshaker.Handshake()
	if err != nil {
		return fmt.Errorf("could not handshake: %w", err)
	}

	glog.Infof("dialing %s", raddr)
	outConn, err := rt.Dialer.Dial(raddr)
	if err != nil {
		return fmt.Errorf("could not dial: %w", err)
	}

	g := new(errgroup.Group)
	g.Go(func() error {
		defer inConn.Close()
		defer outConn.Close()
		return copyConn("->", inConn, outConn)
	})
	g.Go(func() error {
		defer inConn.Close()
		defer outConn.Close()
		return copyConn("<-", outConn, inConn)
	})

	return g.Wait()
}

func copyConn(prefix string, i, o net.Conn) error {
	b := make([]byte, 8*1024)
	for {
		glog.V(1).Infof("%s reading from %s", prefix, i.RemoteAddr())
		n, err := i.Read(b)
		if err != nil {
			return fmt.Errorf("%s could not read from %s: %w", prefix, i.RemoteAddr(), err)
		}
		glog.V(1).Infof("%s read bytes from %s: %d", prefix, i.RemoteAddr(), n)

		/*
		 * // FIXME
		 * if err := o.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		 *   return fmt.Errorf("%s could not set write deadline to %s: %w", prefix, i.RemoteAddr(), err)
		 * }
		 */

		glog.V(1).Infof("%s writing to %s", prefix, o.RemoteAddr())
		m, err := o.Write(b[:n])
		if err != nil {
			return fmt.Errorf("%s could not write to %s: %w", prefix, o.RemoteAddr(), err)
		}
		glog.V(1).Infof("%s written bytes to %s: %d", prefix, o.RemoteAddr(), m)
	}
}
