package transport

import (
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/cirias/tcpproxy/tcpip"
)

func TestTun(t *testing.T) {
	tun, err := NewTUN("", "192.168.200.1/24")
	if err != nil {
		t.Fatal(err)
	}

  if err := tun.EnableDefaultRoute(); err != nil {
    t.Fatal(err)
  }

	tcpListener, err := tun.NewTCPListener("", 12345)
	if err != nil {
		t.Fatal(err)
	}

	ipListener := tun.NewIPListener()

	go func() {
		if err := tun.ReadPackets(tcpListener, ipListener); err != nil {
			fmt.Println(err)
		}
	}()

  {
    g := new(errgroup.Group)
    g.Go(func() error {
      fmt.Println("accepting tcp")
      handshaker, err := tcpListener.Accept()
      if err != nil {
        return err
      }

      fmt.Println(handshaker.RemoteAddr().String())

      c, raddr, err := handshaker.Handshake()
      if err != nil {
        return err
      }
      defer c.Close()
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
      defer c.Close()

      if _, err := c.Write([]byte("hello ")); err != nil {
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

    time.Sleep(time.Second)
  }

  {
    g := new(errgroup.Group)
    g.Go(func() error {
      fmt.Println("accepting ip conn")
      handshaker, err := ipListener.Accept()
      if err != nil {
        return err
      }

      fmt.Println("handshaking with", handshaker.RemoteAddr())

      c, raddr, err := handshaker.Handshake()
      if err != nil {
        return err
      }
      defer c.Close()

      if raddr.String() != "tun_if" {
        return fmt.Errorf("wrong remote address: %s", raddr.String())
      }

      b := make([]byte, 2048)
      n, err := c.Read(b)
      if err != nil {
        return err
      }
      pLen := int(binary.BigEndian.Uint16(b[:2]))
      if 4+pLen != n {
        return fmt.Errorf("len mismatch %d vs %d", 4+pLen, n)
      }

      ip4 := tcpip.IPv4Packet(b[4:n])
      udp := ip4.TransportPacket().(tcpip.UDPPacket)
      if udp == nil {
        return fmt.Errorf("received packet is not UDP")
      }

      if string(udp.Payload()) != "hello " {
        return fmt.Errorf("wrong UDP payload: %s", udp.Payload())
      }

      p := make([]byte, 2048)
      n = tcpip.NewUDPPacket(p[4:], ip4.DstIP(), ip4.SrcIP(), udp.DstPort(), udp.SrcPort(), []byte("world"))
      binary.BigEndian.PutUint16(p[:2], uint16(n))
      p[2] = 0
      p[3] = 0
      if _, err := c.Write(p[:4+n]); err != nil {
        return err
      }

      n = tcpip.NewUDPPacket(p[4:], ip4.DstIP(), ip4.SrcIP(), udp.DstPort(), udp.SrcPort(), []byte("hello2 "))
      binary.BigEndian.PutUint16(p[:2], uint16(n))
      p[2] = 0
      p[3] = 0
      if _, err := c.Write(p[:4+n]); err != nil {
        return err
      }

      {
        n, err := c.Read(b)
        if err != nil {
          return err
        }
        pLen := int(binary.BigEndian.Uint16(b[:2]))
        if 4+pLen != n {
          return fmt.Errorf("len mismatch %d vs %d", 4+pLen, n)
        }

        ip4 := tcpip.IPv4Packet(b[4:n])
        udp := ip4.TransportPacket().(tcpip.UDPPacket)
        if udp == nil {
          return fmt.Errorf("received packet is not UDP")
        }

        if string(udp.Payload()) != "world2" {
          return fmt.Errorf("wrong UDP payload: %s", udp.Payload())
        }
      }

      return nil
    })

    g.Go(func() error {
      time.Sleep(time.Second)

      c, err := net.DialUDP("udp", nil, &net.UDPAddr{
        IP: []byte{1, 1, 1, 1},
        Port: 443,
      })
      if err != nil {
        return err
      }
      defer c.Close()

      b := make([]byte, 10)
      {
        if _, err := c.Write([]byte("hello ")); err != nil {
          return err
        }

        n, err := c.Read(b)
        if  err != nil {
          return err
        }

        if string(b[:n]) != "world" {
          return fmt.Errorf("wrong UDP payload: %s", b[:n])
        }
      }

      {
        n, err := c.Read(b)
        if  err != nil {
          return err
        }

        if string(b[:n]) != "hello2 " {
          return fmt.Errorf("wrong UDP payload: %s", b[:n])
        }

        if _, err := c.Write([]byte("world2")); err != nil {
          return err
        }
      }

      return nil
    })

    if err := g.Wait(); err != nil {
      t.Fatal(err)
    }

    time.Sleep(time.Second)
  }
}
