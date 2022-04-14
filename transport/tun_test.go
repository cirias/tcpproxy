package transport

import (
  "fmt"
	"net"
	"testing"
  "time"

  "golang.org/x/sync/errgroup"
)

func TestTun(t *testing.T) {
  helper, err := NewTUNHelper("", "192.168.200.1/24")
  if err != nil {
    t.Fatal(err)
  }

  tcpListener, err := helper.NewTCPListener("192.168.200.2", "192.168.200.1:12345")
  if err != nil {
    t.Fatal(err)
  }

  go func() {
    if err := helper.ReadPackets(tcpListener, nil); err != nil {
      fmt.Println(err)
    }
  }()

  g := new(errgroup.Group)
  g.Go(func() error {
    fmt.Println("accepting")
    handshaker, err := tcpListener.Accept()
    if err != nil {
      return err
    }

    fmt.Println(handshaker.RemoteAddr().String())

    c, raddr, err := handshaker.Handshake()
    if err != nil {
      return err
    }
    fmt.Println(raddr.String())

    b := make([]byte, 10)
    n, err := c.Read(b)
    if err != nil {
      return err
    }
    fmt.Println(string(b[:n]))

    if _, err := c.Write([]byte("world")); err != nil {
      return err
    }
    return nil
  })

  g.Go(func() error {
    time.Sleep(time.Second)

    fmt.Println("dialing")
    c, err := net.Dial("tcp", "1.1.1.1:443")
    if err != nil {
      return err
    }

    if _, err := c.Write([]byte("hello")); err != nil {
      return err
    }

    b := make([]byte, 10)
    n, err := c.Read(b)
    if err != nil {
      return err
    }
    fmt.Println(string(b[:n]))

    return nil
  })

  if err := g.Wait(); err != nil {
    t.Fatal(err)
  }
}
