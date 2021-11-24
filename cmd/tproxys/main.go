package main

import (
	"flag"

	"github.com/golang/glog"

	"github.com/cirias/tcpproxy/transport"
)

var secret = flag.String("secret", "", "secret shared with client")
var laddr = flag.String("laddr", "0.0.0.0:443", "local listening address")
var cert = flag.String("cert", "", "path of the cert file")
var key = flag.String("key", "", "path of the cert key file")
var cacert = flag.String("cacert", "", "path of the CA cert file for verify client cert (optional)")

func main() {
	flag.Parse()

	listener, err := transport.ListenTLSTunnelWithCertFile(*secret, *laddr, *cert, *key, *cacert)
	if err != nil {
		glog.Fatalln(err)
	}

	dialer := &transport.TCPDialer{}

	rt := &transport.RoundTripper{Listener: listener, Dialer: dialer}

	glog.Fatalln(rt.RoundTrip())
}
