package transport

import (
	"encoding/binary"
	"fmt"
	"net"
	"os/exec"
	"testing"
	"time"

	"github.com/golang/glog"
	"golang.org/x/sync/errgroup"

	wgtun "golang.zx2c4.com/wireguard/tun"

	"github.com/cirias/tcpproxy/tcpip"
)

const (
	tunAddr       = "192.168.200.1/24"
	proxyNet      = "192.168.200.128/25"
	tunRouteTable = "400"
)

func TestTun(t *testing.T) {
	tun, err := wgtun.CreateTUN("", 1420)
	if err != nil {
		t.Fatal(err)
	}

	tunName, err := tun.Name()
	if err != nil {
		t.Fatal(err)
	}

	if err := exec.Command("ip", "address", "add", tunAddr, "dev", tunName).Run(); err != nil {
		t.Fatal(err)
	}

	if err := exec.Command("ip", "link", "set", "dev", tunName, "up").Run(); err != nil {
		t.Fatal(err)
	}

	if err := enableDefaultRoute(tunName); err != nil {
		t.Fatal(err)
	}

	tcpListener, err := NewTUNTCPListener(tun, tunAddr, proxyNet, 12345)
	if err != nil {
		t.Fatal(err)
	}

	ipListener := NewTUNIPListener(tun)

	go func() {
		if err := TUNReadPacketsRoutine(tun, tcpListener, ipListener); err != nil {
			fmt.Println(err)
		}
	}()

	{
		g := new(errgroup.Group)
		g.Go(func() error {
			fmt.Println("accepting tcp")
			answerer, err := tcpListener.Accept()
			if err != nil {
				return err
			}

			fmt.Println(answerer.RemoteAddr().String())

			c, raddr, err := answerer.Answer()
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
			answerer, err := ipListener.Accept()
			if err != nil {
				return err
			}

			fmt.Println("handshaking with", answerer.RemoteAddr())

			c, raddr, err := answerer.Answer()
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
				IP:   []byte{1, 1, 1, 1},
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
				if err != nil {
					return err
				}

				if string(b[:n]) != "world" {
					return fmt.Errorf("wrong UDP payload: %s", b[:n])
				}
			}

			{
				n, err := c.Read(b)
				if err != nil {
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

func enableDefaultRoute(ifname string) error {
	// ugly way to clean the previous created rules
	for {
		if err := exec.Command("ip", "rule", "del", "not", "fwmark", fmt.Sprint(tcpproxyBypassMark), "table", tunRouteTable).Run(); err != nil {
			break
		}
	}
	if err := exec.Command("ip", "rule", "add", "not", "fwmark", fmt.Sprint(tcpproxyBypassMark), "table", tunRouteTable).Run(); err != nil {
		return fmt.Errorf("could not set bypass rule: %w", err)
	}

	for {
		if err := exec.Command("ip", "rule", "del", "lookup", "main", "suppress_prefixlength", "0").Run(); err != nil {
			break
		}
	}
	if err := exec.Command("ip", "rule", "add", "lookup", "main", "suppress_prefixlength", "0").Run(); err != nil {
		return fmt.Errorf("could not set bypass rule: %w", err)
	}

	if err := exec.Command("ip", "route", "add", "table", tunRouteTable, "default", "dev", ifname, "scope", "link").Run(); err != nil {
		return fmt.Errorf("could not set route table for tun device: %w", err)
	}

	glog.Infof("enabled default route to %s", ifname)

	return nil
}
