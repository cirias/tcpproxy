package main

import (
	"flag"
	"fmt"

	"github.com/golang/glog"

	"github.com/cirias/tcpproxy/transport"
)

var secret = flag.String("secret", "", "secret shared with client")
var laddr = flag.String("laddr", "", "local listening address")
var raddr = flag.String("raddr", "", "remote connecting address")
var sname = flag.String("sname", "", "TLS server name")
var cacert = flag.String("cacert", "", "path of the CA cert file for verify server cert (optional)")

var tname = flag.String("tun", "", "TUN device name")
var tunip = flag.String("tunip", "", "TUN device IP address in CIDR")
var tunproxyip = flag.String("tunproxyip", "", "TUN device proxy IP for TCP")
var tunproxyport = flag.Int("tunproxyport", 0, "TUN device proxy port that TCP server bind to")

func main() {
	flag.Parse()

	if *tunip != "" && *laddr != "" {
		fmt.Println("ignoring laddr because tunip is provided")
	}

	listeners := make([]transport.Listener, 0, 2)
	if tunip != nil {
		tun, err := transport.NewTUN(*tname, *tunip)
		if err != nil {
			glog.Fatal(err)
		}

		ipListener := tun.NewIPListener()
		listeners = append(listeners, ipListener)

		var tcpListener *transport.TUNTCPListener
		if *tunproxyport != 0 {
			var err error
			tcpListener, err = tun.NewTCPListener(*tunproxyip, *tunproxyport)
			if err != nil {
				glog.Fatal(err)
			}

			listeners = append(listeners, tcpListener)
		}

		go func() {
			if err := tun.ReadPackets(tcpListener, ipListener); err != nil {
				glog.Fatal(err)
			}
		}()
	} else {
		listener, err := transport.ListenRedirectTCP(*laddr)
		if err != nil {
			glog.Fatalln(err)
		}
		listeners = append(listeners, listener)
	}

	dialer, err := transport.NewTLSTunnelDialerWithCertFile(*secret, "", *raddr, *sname, *cacert)
	// dialer, err := transport.NewTCPDialer(*secret, "", *raddr)
	if err != nil {
		glog.Fatalln(err)
	}

	rt := &transport.RoundTripper{Listeners: listeners, Dialer: dialer}

	glog.Fatalln(rt.RoundTrip())
}
