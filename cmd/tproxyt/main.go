package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"syscall"

	"github.com/golang/glog"
	"golang.org/x/sync/errgroup"

	wgtun "golang.zx2c4.com/wireguard/tun"

	"github.com/cirias/tcpproxy/transport"
)

const ExitSetupFailed = 1

const (
	ENV_TP_TUN_FD             = "TP_TUN_FD"
	ENV_TP_PROCESS_FOREGROUND = "TP_PROCESS_FOREGROUND"
)

const DefaultMTU = 1420

var foreground = flag.Bool("foreground", false, "Run process in foreground. Default false")
var mode = flag.String("mode", "", "server or client")
var secret = flag.String("secret", "", "secret shared with client")
var cacert = flag.String("cacert", "", "path of the CA cert file for verify client/server cert (optional)")
var tname = flag.String("tun", "", "TUN device name")
var tunip = flag.String("tunip", "", "TUN device IP address in CIDR")

// client
var raddr = flag.String("raddr", "", "remote connecting address")
var sname = flag.String("sname", "", "TLS server name")
var tunproxyip = flag.String("tunproxyip", "", "TUN device proxy IP for TCP")
var tunproxyport = flag.Int("tunproxyport", 0, "TUN device proxy port that TCP server bind to")

// server
var laddr = flag.String("laddr", "0.0.0.0:443", "local listening address")
var faddr = flag.String("faddr", "", "fallback http server address (optional)")
var cert = flag.String("cert", "", "path of the cert file")
var key = flag.String("key", "", "path of the cert key file")

func main() {
	flag.Parse()

	var run func(wgtun.Device) error
	switch *mode {
	case "client":
		run = client
	case "server":
		run = server
	default:
		flag.PrintDefaults()
		os.Exit(ExitSetupFailed)
	}

	if !*foreground {
		*foreground = os.Getenv(ENV_TP_PROCESS_FOREGROUND) == "1"
	}

	tun, err := createTUN()
	if err != nil {
		glog.Fatalf("could not create TUN device: %s", err)
	}

	if !*foreground {
		env := os.Environ()
		env = append(env, fmt.Sprintf("%s=3", ENV_TP_TUN_FD))
		// env = append(env, fmt.Sprintf("%s=4", ENV_TP_UAPI_FD))
		env = append(env, fmt.Sprintf("%s=1", ENV_TP_PROCESS_FOREGROUND))
		files := [3]*os.File{}
		// if os.Getenv("LOG_LEVEL") != "" && logLevel != device.LogLevelSilent {
		files[0], _ = os.Open(os.DevNull)
		files[1] = os.Stdout
		files[2] = os.Stderr
		/*
		 * } else {
		 *   files[0], _ = os.Open(os.DevNull)
		 *   files[1], _ = os.Open(os.DevNull)
		 *   files[2], _ = os.Open(os.DevNull)
		 * }
		 */
		attr := &os.ProcAttr{
			Files: []*os.File{
				files[0], // stdin
				files[1], // stdout
				files[2], // stderr
				tun.File(),
				// fileUAPI,
			},
			Dir: ".",
			Env: env,
		}

		path, err := os.Executable()
		if err != nil {
			glog.Errorf("Failed to determine executable: %v", err)
			os.Exit(ExitSetupFailed)
		}

		process, err := os.StartProcess(
			path,
			os.Args,
			attr,
		)
		if err != nil {
			glog.Errorf("Failed to daemonize: %v", err)
			os.Exit(ExitSetupFailed)
		}
		process.Release()
		return
	}

	for {
		event := <-tun.Events()
		// FIXME: somehow EventUP received when the device is not really up
		// use EventMTUUpdate instead
		if event&wgtun.EventMTUUpdate != 0 {
			break
		}
	}
	glog.Infof("TUN device up")

	glog.Fatalln(run(tun))
}

func createTUN() (wgtun.Device, error) {
	tunFdStr := os.Getenv(ENV_TP_TUN_FD)
	if tunFdStr == "" {
		return wgtun.CreateTUN(*tname, DefaultMTU)
	}

	// construct tun device from supplied fd

	fd, err := strconv.ParseUint(tunFdStr, 10, 32)
	if err != nil {
		return nil, err
	}

	err = syscall.SetNonblock(int(fd), true)
	if err != nil {
		return nil, err
	}

	file := os.NewFile(uintptr(fd), "")
	return wgtun.CreateTUNFromFile(file, DefaultMTU)
}

func client(tun wgtun.Device) error {
	ttun, err := transport.NewTUN(tun, *tunip)
	if err != nil {
		return err
	}

	ipListener := ttun.NewIPListener()

	var tcpListener *transport.TUNTCPListener
	if *tunproxyport != 0 {
		var err error
		tcpListener, err = ttun.NewTCPListener(*tunproxyip, *tunproxyport)
		if err != nil {
			return err
		}
	}

	var wg errgroup.Group
	wg.Go(func() error { return ttun.ReadPackets(tcpListener, ipListener) })
	wg.Go(func() error {
		dialer, err := transport.NewTLSTunnelDialerWithCertFile(*secret, "", *raddr, *sname, *cacert)
		// dialer, err := transport.NewTCPDialer(*secret, "", *raddr)
		if err != nil {
			return err
		}

		listeners := []transport.Listener{ipListener, tcpListener}
		rt := &transport.RoundTripper{Listeners: listeners, Dialer: dialer}

		return rt.RoundTrip()
	})
	return wg.Wait()
}

func server(tun wgtun.Device) error {
	listener, err := transport.ListenTLSTunnelWithCert(*secret, *laddr, *faddr, *cert, *key, *cacert)
	// listener, err := transport.ListenTCPTunnel(*secret, *laddr, *faddr)
	if err != nil {
		return err
	}

	ttun, err := transport.NewTUN(tun, *tunip)
	if err != nil {
		return err
	}

	ipDialer := ttun.NewIPDialer()

	var wg errgroup.Group
	wg.Go(func() error { return ipDialer.ReadPackets() })
	wg.Go(func() error {
		dialer := &transport.TUNTCPDialer{
			TCP: &transport.TCPDialer{},
			IP:  ipDialer,
		}

		rt := &transport.RoundTripper{Listeners: []transport.Listener{listener}, Dialer: dialer}

		return rt.RoundTrip()
	})
	return wg.Wait()
}
