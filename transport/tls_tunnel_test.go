package transport

import (
	"log"
	"net"
	"testing"
)

func TestTLSTunnel(t *testing.T) {
	secret := "s0cr2t"
	certPEMBlock := []byte(`
-----BEGIN CERTIFICATE-----
MIIDWzCCAkOgAwIBAgIURLJ7/3mBjGEccLtAVQgUZB0Mc+owDQYJKoZIhvcNAQEL
BQAwWTELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRIwEAYDVQQHDAlTb21ld2hl
cmUxEDAOBgNVBAoMB1NvbWVvbmUxFzAVBgNVBAMMDmNhLmV4YW1wbGUuY29tMB4X
DTIxMTEwNDA3MDUyM1oXDTIxMTIwNDA3MDUyM1owWDELMAkGA1UEBhMCVVMxCzAJ
BgNVBAgMAkNBMRIwEAYDVQQHDAlTb21ld2hlcmUxEDAOBgNVBAoMB1NvbWVvbmUx
FjAUBgNVBAMMDXMuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQDaHnABAOEdlwPmsJA7RS8d/qtRYJ8ZFqS7UcmfSD71zKYf7HZ8x5nM
XYX9g3i/SPjNwvuuiUR/RMkoKdsoj5ceYnPodmQIhrdvQhzoiziEWFHQU5qdKl85
Dmf3RrJwLAAjMoeLmBI5b+jmsDBvKGvAryRmpKq5+ZSa/oVVbpvsfefwTbP+E0rB
KnSU8fn3mz/Hc2Zt4uRQDzRr370DhC3e/rlR+HlCp1inHR7ncs+5n4ES1E8OUXmP
bCn1yPtjubs0u0LNkTBq0IjY7uOLNDxROlOIZDiW+NnOmJGbzV7bHu/wW/KWTeYo
XG+dKbARsH6DvQLCfw43pCZvRyRoWjvZAgMBAAGjHDAaMBgGA1UdEQQRMA+CDSou
ZXhhbXBsZS5jb20wDQYJKoZIhvcNAQELBQADggEBAFNWs1VooH+kVzn5BOfNn/FZ
xUP2RQxAbv1tKPQqHAJo5DF4/du0f4bmaLGY8AT23HwXGolSVetM2YR1rNIJNipe
oGttwWgRVU+NGfYp7XYjLSOOAn1w4xpqsn10NQXUNU9IgQeprafni94+1tkjQdn0
yvrTsAwmsIU/TNEYVaJt/3yEds0ajK33LL5pNRPUt29A9t1j3A38Fp6aZyYtKnPR
BhEOqYVswLRhoPLqeypudQEGlH5tRDde5Lx0O3NrSAmTpCwoCCPdv0gEmqha+Z2l
eY4Je5JIK+BhbijZ0QpHn3eWhGLRPL+A4dbGwCqPrWhKkwu1fNIrEcygQta52NM=
-----END CERTIFICATE-----
  `)
	keyPEMBlock := []byte(`
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEA2h5wAQDhHZcD5rCQO0UvHf6rUWCfGRaku1HJn0g+9cymH+x2
fMeZzF2F/YN4v0j4zcL7rolEf0TJKCnbKI+XHmJz6HZkCIa3b0Ic6Is4hFhR0FOa
nSpfOQ5n90aycCwAIzKHi5gSOW/o5rAwbyhrwK8kZqSqufmUmv6FVW6b7H3n8E2z
/hNKwSp0lPH595s/x3NmbeLkUA80a9+9A4Qt3v65Ufh5QqdYpx0e53LPuZ+BEtRP
DlF5j2wp9cj7Y7m7NLtCzZEwatCI2O7jizQ8UTpTiGQ4lvjZzpiRm81e2x7v8Fvy
lk3mKFxvnSmwEbB+g70Cwn8ON6Qmb0ckaFo72QIDAQABAoIBACkYqwnFXKTymy2P
/tzsACCqpyTCC7fyaD9S/aYhOpudX3+MUhbYlMXIqUJGzy1bVmWOY1VTT7CbCTuk
B0LxKwvyiNw30kk4+L7hugimkpN9AI0781nBbgeWC0iv7VbtM2luT9OhZ22jBELS
141aFFNNrJIaXICF4dYCNqUOHhrElS8OtlY+lYw8IYMI/Kyolb1qWzZ++Mh7Viu/
O4JCXr9nrQRfsTcaTOukMYbGVyb5zlGXK+mOTXYy87NlL9Jwja81mz8UUdczyBwi
Fmg80bqPI10UnOYQ6Z7NJB4rOWtUdUuCKSXvBGdcSQ8Qe376XND//xwMpBFOa/iA
tn5FEnECgYEA7Ncf+Ia+aTM+lqhJKEDvftbD7IexNVIK5S4Sos44x1H8V2+NsKwF
gSrcqf9+3hiTTuSjWqFnwhKlOrFg45ThhodyANknuyLSqbejJtEubUJaaohuOe8x
Pk6nmiDQcsdEYEiMNyT9CChT2ec3YECI+jwp+pbREkIvWSQ/e6xe3msCgYEA68OZ
QvOKCuCQ8O6uTGnaZIQ2jbOP/PTPLiwGgRdmvv+mKD+H8P/g3encLAiL6WRS/XNS
l7JHMorzA17CaxNrJv+mFieBPVB/6uhchN4c0niXJF8/A34css7/ay4LRv8/o09r
yjOyV7CS5pRUHT3q+7WvuQ5UASSXRg8kNRH818sCgYAb3rTEaha+CmmzENqLAhks
s9kaXF1eCOl/Toyi2+GSkvM+1sG1qIh9Sq3s00P6nqm2/vC6GYQ8MjV/UqA0J7Di
Q84Gi4dBXjesARAR4Uu1T7mUD7no11zUGC1g1buxxgEl02OsmY2tCBHV8n9xtCZq
S+okstqna2Jm+vz9cKs5QQKBgHRJXN3mC6+DxlngED6Gc37iq5nG+H1XLp1if67K
oRYSOJ1fgKjBPOOYBs39RS1QG5MBf7ps56spV+XQpmp0AIUS0ZPZ1mgsvXtbMs8i
UusJKdt50zXgzTzw1pDB/DP/kB73/H2WdB/Gax6qCLcHpFCU8+B+DbcmmiqnKz+1
6JVzAoGAXHyATgA5SHrqnweTxCb5yGReYBwg3ETF7RvMUoEYZzHlN7q2hjaKmZsA
N0o0dtCOh02hwpKIEdugE/rrrw+6492boyFr8TQKBw0Nq4gsVmRTYnrjmgfqFqGu
8xscB2d+yCngKI+XPepfEJIyD/weaZkhSbSoaoLBoWIi5rVQOnY=
-----END RSA PRIVATE KEY-----
  `)
	caCertPEMBlock := []byte(`
-----BEGIN CERTIFICATE-----
MIIDkzCCAnugAwIBAgIUWofCkuz9t2BvfsOSVc6QtwnMcsEwDQYJKoZIhvcNAQEL
BQAwWTELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRIwEAYDVQQHDAlTb21ld2hl
cmUxEDAOBgNVBAoMB1NvbWVvbmUxFzAVBgNVBAMMDmNhLmV4YW1wbGUuY29tMB4X
DTIxMTEwNDA3MDMwMFoXDTIxMTIwNDA3MDMwMFowWTELMAkGA1UEBhMCVVMxCzAJ
BgNVBAgMAkNBMRIwEAYDVQQHDAlTb21ld2hlcmUxEDAOBgNVBAoMB1NvbWVvbmUx
FzAVBgNVBAMMDmNhLmV4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEAx+CrsqCO/G2DnY/rTPwBvWGgBlGolueU291DDOdg8SDaMnonHQOg
soy5QDuQfqNaGPyrkoWIbAybcWUozqD71a+3iO3pqnTIzdtj2wOJn47RHDaR9+Qc
jZt+6RpMGdfbEi7dBOS0I/eqkadvs5I9J1+Q5UhXaXCIPwwwUQ8Akaq3UeONQdIj
It+Ycxvd50DakYAhgJk2klGZtSiOXpnxeTKA5tlK6W9DDHHCmV0jAANsrNBIiH8q
AYkywjAvW3rzy9EhdpF9wuOlQaGKEcxit2t6mjBq6Ihrk6n9GotBWmEq60w3Tj+A
5WfAUYTGzjRkdy748NthxHTEokmNlhpSIQIDAQABo1MwUTAdBgNVHQ4EFgQU3cKy
yVA0ZKKk3V90IZi9zpRvEPgwHwYDVR0jBBgwFoAU3cKyyVA0ZKKk3V90IZi9zpRv
EPgwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAQWTyxwPOg4kO
kDdIphER2bVXoYLJohmFPimW7qwqHi3qHy99hmgh9jTHUnKyrg+QpKtpfCJ4koNs
pm5j0MkAirJgf6Y17lgIz9caIhcTjDn2+poay1XE/7v9fkkF7jJaQ62tAZU6HXHm
CCI9SMnj3thQ1HuKeNPVr5SBl6TtkQGQ1WMtkryFUzsu9QzRgmGW9waUlsCMyjuz
kE0m4LxPOm3Fk6uT/WNeVSUuw9mniguu3vIj6LDco6Aojf4LEHBdhALCRigKgAad
YarFhZrX6kCjnIQDGsSRFcpR/LpmVGQmqkh/ts16fXP9Zfg/sFrUceTdv+qfHXJT
yWjChbbGsQ==
-----END CERTIFICATE-----
  `)

	listener, err := ListenTLSTunnelWithCert(secret, "", "", certPEMBlock, keyPEMBlock, nil)
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
