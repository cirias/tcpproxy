package main

import (
	"flag"

	"github.com/golang/glog"

	"github.com/cirias/tcpproxy/transport"
)

var secret = flag.String("secret", "", "secret shared with client")
var laddr = flag.String("laddr", "0.0.0.0:443", "local listening address")
var faddr = flag.String("faddr", "", "fallback http server address")
var cert = flag.String("cert", "", "path of the cert file")
var key = flag.String("key", "", "path of the cert key file")
var cacert = flag.String("cacert", "", "path of the CA cert file for verify client cert (optional)")

var tname = flag.String("tun", "", "TUN device name")
var tunip = flag.String("tunip", "", "TUN device IP address in CIDR")

func main() {
	flag.Parse()

	listener, err := transport.ListenTLSTunnelWithCertFile(*secret, *laddr, *faddr, *cert, *key, *cacert)
	// listener, err := transport.ListenTCPTunnel(*secret, *laddr, *faddr)
	if err != nil {
		glog.Fatalln(err)
	}

	tcpDialer := &transport.TCPDialer{}
	var dialer transport.Dialer = tcpDialer
	if *tunip != "" {
		tun, err := transport.NewTUN(*tname, *tunip)
		if err != nil {
			glog.Fatal(err)
		}

		ipDiailer := tun.NewIPDialer()

		dialer = &transport.TUNTCPDialer{
			TCP: tcpDialer,
			IP:  ipDiailer,
		}
	}

	rt := &transport.RoundTripper{Listeners: []transport.Listener{listener}, Dialer: dialer}

	glog.Fatalln(rt.RoundTrip())
}
