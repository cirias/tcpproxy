package transport

import (
	"log"
	"net"
	"testing"
)

func TestTLSTunnel(t *testing.T) {
	secret := "s0cr2t"
	caCertPEMBlock := []byte(`
-----BEGIN CERTIFICATE-----
MIIDlTCCAn2gAwIBAgIUIVxAyAzPAkMUEMfGnFSBE5HqQ64wDQYJKoZIhvcNAQEL
BQAwWTELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRIwEAYDVQQHDAlTb21ld2hl
cmUxEDAOBgNVBAoMB1NvbWVvbmUxFzAVBgNVBAMMDmNhLmV4YW1wbGUuY29tMCAX
DTIxMTIwNDEwMDgwOVoYDzIxMjExMTEwMTAwODA5WjBZMQswCQYDVQQGEwJVUzEL
MAkGA1UECAwCQ0ExEjAQBgNVBAcMCVNvbWV3aGVyZTEQMA4GA1UECgwHU29tZW9u
ZTEXMBUGA1UEAwwOY2EuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQDUdvAj2Xjl0MfxjuRLA0/0bK0aqiBNwrNf9zEGbKKLSZZgd0Ms
I+jzdeG3pZ65g/a3jwIU2TN2U7Lu3UzhZGl3JBGzblVxobFNWhIbzshQW+ASRPBl
F54dj/pweGrHrRXCmMgW5spYOm3Zf3uhLUTcpUhRNOwLKygixcanyatniTLycwXE
GpaNaN6eS3L9rO7xpktfGxhTf8vrBHI9Y3uECix0fU66zEsz22lMmpbriOM+EVhS
aXdaqOsBfj3ibx8PyBxOgh13sp9Mp1YGvXjOQzBYBXiWoRe6SYyvHoY1BfTHEc7a
n/oP377gjgcHEVSgIUFjGPC3W+87pTO7CPD3AgMBAAGjUzBRMB0GA1UdDgQWBBQB
bJL0bAiCtErxBgufKn3PlWVEyTAfBgNVHSMEGDAWgBQBbJL0bAiCtErxBgufKn3P
lWVEyTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBNiMzLPQb/
tZ2NrL4hFBvomrqIryNrtoMddj/Uj2bC+j0svPte5WGCsp11n3SB/463gm31bClu
noz18olLjfEDQPxKJVqXEcUzjoKYmW/6yGF2CwAjlwPSnWTWp/yj7/rOD+58fpOW
T0Yqx9NfAIcDHMmqO2IGyl4qbqms/IgewcEf0W9fOPyt9QrLy8UGQnspE79vIBNh
JaHRQVIC9TUoRMmCaVrxh5Bl3mf6a4v3UmumxgYFsDOAt4oHy/50hhq6yLfXnQvh
nDQTCWb4eEHJML1mpEVnD7IqFwpofPgRttkmR0h03t3q+n7qj2+z7u8aa54nur9I
GuCElY3+yMK/
-----END CERTIFICATE-----
  `)

	listener, err := ListenTLSTunnelWithCert(secret, "", "", "test/ssl/server_cert.pem", "test/ssl/server_key.pem", "")
	if err != nil {
		t.Fatal(err)
	}

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
