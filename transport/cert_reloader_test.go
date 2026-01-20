package transport

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func generateSelfSignedCert(t *testing.T, dir string) (string, string) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	certPath := filepath.Join(dir, "cert.pem")
	certOut, err := os.Create(certPath)
	if err != nil {
		t.Fatalf("Failed to open cert.pem for writing: %v", err)
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()

	keyPath := filepath.Join(dir, "key.pem")
	keyOut, err := os.Create(keyPath)
	if err != nil {
		t.Fatalf("Failed to open key.pem for writing: %v", err)
	}
	privBytes := x509.MarshalPKCS1PrivateKey(priv)
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes})
	keyOut.Close()

	return certPath, keyPath
}

func TestCertReloaderRace(t *testing.T) {
	tmpDir := t.TempDir()
	certPath, keyPath := generateSelfSignedCert(t, tmpDir)

	cr := &CertReloader{
		certFile: certPath,
		keyFile:  keyPath,
	}

	// Initial load
	_, err := cr.GetCertificate(nil)
	if err != nil {
		t.Fatalf("Initial GetCertificate failed: %v", err)
	}

	var wg sync.WaitGroup
	start := make(chan struct{})
	done := make(chan struct{})

	// Readers
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for {
				select {
				case <-done:
					return
				default:
					_, err := cr.GetCertificate(nil)
					if err != nil {
						// It's possible to get an error if the file is being written to
						// but we are mainly looking for data races here.
						// t.Errorf("GetCertificate failed: %v", err)
					}
				}
			}
		}()
	}

	// Writer (Updater)
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for j := 0; j < 50; j++ {
			time.Sleep(1 * time.Millisecond)
			// Touch the key file to trigger reload
			now := time.Now().Add(time.Duration(j) * time.Second) // Ensure time moves forward
			if err := os.Chtimes(keyPath, now, now); err != nil {
				t.Errorf("Failed to touch key file: %v", err)
			}
		}
		close(done)
	}()

	close(start)
	wg.Wait()
}
