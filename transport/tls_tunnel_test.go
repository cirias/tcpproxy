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

func generateTestCert(t *testing.T, dir string) (string, string, []byte) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			CommonName:   "s.example.com",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"s.example.com"},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	certPath := filepath.Join(dir, "server_cert.pem")
	certOut, err := os.Create(certPath)
	if err != nil {
		t.Fatalf("Failed to open cert.pem for writing: %v", err)
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()

	keyPath := filepath.Join(dir, "server_key.pem")
	keyOut, err := os.Create(keyPath)
	if err != nil {
		t.Fatalf("Failed to open key.pem for writing: %v", err)
	}
	privBytes := x509.MarshalPKCS1PrivateKey(priv)
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes})
	keyOut.Close()

	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	return certPath, keyPath, caCertPEM
}

func TestTLSTunnel(t *testing.T) {
	secret := "s0cr2t"
	tmpDir := t.TempDir()
	certPath, keyPath, caCertPEMBlock := generateTestCert(t, tmpDir)

	listener, err := ListenTLSTunnelWithCert(secret, "", "", certPath, keyPath, "")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	dialer, err := NewTLSTunnelDialerWithCert(secret, "", listener.Addr().String(), "s.example.com", caCertPEMBlock)
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
		defer conn.Close()

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
	defer conn.Close()

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
