package transport

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeTestCerts(t *testing.T, serverName string) (string, string, []byte) {
	t.Helper()

	now := time.Now()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}

	caTemplate := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "tcpproxy-test-ca"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	if caPEM == nil {
		t.Fatal("encode CA cert")
	}

	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}
	serverTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: serverName},
		DNSNames:     []string{serverName},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	serverDER, err := x509.CreateCertificate(rand.Reader, &serverTemplate, &caTemplate, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create server cert: %v", err)
	}
	serverCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER})
	if serverCertPEM == nil {
		t.Fatal("encode server cert")
	}
	serverKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverKey)})
	if serverKeyPEM == nil {
		t.Fatal("encode server key")
	}

	dir := t.TempDir()
	certFile := filepath.Join(dir, "server_cert.pem")
	keyFile := filepath.Join(dir, "server_key.pem")
	if err := os.WriteFile(certFile, serverCertPEM, 0o600); err != nil {
		t.Fatalf("write server cert: %v", err)
	}
	if err := os.WriteFile(keyFile, serverKeyPEM, 0o600); err != nil {
		t.Fatalf("write server key: %v", err)
	}

	return certFile, keyFile, caPEM
}

func TestTLSTunnel(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TLS tunnel test in short mode")
	}
	if os.Geteuid() != 0 {
		t.Skip("skipping TLS tunnel test; requires root for SO_MARK")
	}
	secret := "s0cr2t"
	serverName := "s.example.com"
	certFile, keyFile, caCertPEMBlock := writeTestCerts(t, serverName)

	listener, err := ListenTLSTunnelWithCert(secret, "", "", certFile, keyFile, "")
	if err != nil {
		t.Fatal(err)
	}

	dialer, err := NewTLSTunnelDialerWithCert(secret, "", listener.Addr().String(), serverName, caCertPEMBlock)
	if err != nil {
		t.Fatal(err)
	}

	testAddr := net.TCPAddr{IP: net.IP{1, 2, 3, 4}, Port: 5678}
	testTexts := []string{"abcd", "efgh"}

	done := make(chan struct{})
	go func() {
		defer close(done)

		conn, err := dialer.Dial(&testAddr)
		if err != nil {
			log.Fatal(err)
		}

		if _, err := conn.Write([]byte(testTexts[0])); err != nil {
			log.Fatal(err)
		}

		b := make([]byte, 4096)
		n, err := conn.Read(b)
		if err != nil {
			log.Fatal(err)
		}
		if string(b[:n]) != testTexts[1] {
			log.Fatal("wrong read value from client", string(b[:n]))
		}
	}()

	h, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}

	conn, raddr, err := h.Handshake()
	if err != nil {
		t.Fatal(err)
	}
	if raddr.Network() != testAddr.Network() {
		t.Fatal("wrong handshake raddr network", raddr.Network())
	}
	if raddr.String() != testAddr.String() {
		t.Fatal("wrong handshake raddr address", raddr.String())
	}

	b := make([]byte, 4096)
	n, err := conn.Read(b)
	if err != nil {
		t.Fatal(err)
	}
	if string(b[:n]) != testTexts[0] {
		t.Fatal("wrong read value from server", string(b[:n]))
	}
	if _, err := conn.Write([]byte(testTexts[1])); err != nil {
		t.Fatal(err)
	}

	<-done
}
