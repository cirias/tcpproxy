package main

import (
	"flag"

	"github.com/golang/glog"

	"github.com/cirias/tcpproxy/transport"
)

var secret = flag.String("secret", "", "secret shared with client")
var laddr = flag.String("laddr", "", "local listening address")
var raddr = flag.String("raddr", "", "remote connecting address")
var sname = flag.String("sname", "", "TLS server name")
var cacert = flag.String("cacert", "", "path of the CA cert file for verify server cert (optional)")

func main() {
	flag.Parse()

	listener, err := transport.ListenRedirectTCP(*laddr)
	if err != nil {
		glog.Fatalln(err)
	}

	dialer, err := transport.NewTLSTunnelDialerWithCertFile(*secret, "", *raddr, *sname, *cacert)
	if err != nil {
		glog.Fatalln(err)
	}

	rt := &transport.RoundTripper{Listener: listener, Dialer: dialer}

	glog.Fatalln(rt.RoundTrip())
}
