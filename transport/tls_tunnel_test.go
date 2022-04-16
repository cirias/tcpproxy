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
MIIDXTCCAkWgAwIBAgIUIFot1fv5Am4hI2vPzKNFGthEJJwwDQYJKoZIhvcNAQEL
BQAwWTELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRIwEAYDVQQHDAlTb21ld2hl
cmUxEDAOBgNVBAoMB1NvbWVvbmUxFzAVBgNVBAMMDmNhLmV4YW1wbGUuY29tMCAX
DTIxMTIwNDEwMDg1OFoYDzIxMjExMTEwMTAwODU4WjBYMQswCQYDVQQGEwJVUzEL
MAkGA1UECAwCQ0ExEjAQBgNVBAcMCVNvbWV3aGVyZTEQMA4GA1UECgwHU29tZW9u
ZTEWMBQGA1UEAwwNcy5leGFtcGxlLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEP
ADCCAQoCggEBAKgcD8lFDAPzKXlUxeb94Iz3A9VJBWoXpEk9OcynL8Wgz/6EAjeS
3bim6EdHVTD8XrrwnKkiFzMQCVR61cBE+Cylhy8sxVpz79Ay30T3WSPn1PmlkhLp
ZRQhlJELqowaS3wcexjhqolcPZspt+TCx01pWcCeb2nsfFU5wo8AFu2pvgUzpnVH
hUm38hM0wpOqg484d3D6zl0wf/9BQXo3AjtmZ4lwjstHMn3Z2QyMeyEuQohYHQ36
3hn4EkdZr/HqHm7dLumERkAdzcnLNIuevxoOlDHbUSmjZ4AGf+Q9MxvQmMDflve7
YSM+z0wnWYzkK8bjXoUI9jl0w0eGX99OKvUCAwEAAaMcMBowGAYDVR0RBBEwD4IN
Ki5leGFtcGxlLmNvbTANBgkqhkiG9w0BAQsFAAOCAQEAmz4cBvHqV6K7cJ1wUcTx
ldQuNxkw3iETjqFbPQnu83AKDfWthVZv9jJfpKkv3Rh8G7fRDONpkGoiAIgPiY+O
aR80ddiFuPbGDIul5jImWqaBaYmxaSvS9QmnRk5PyevUL0pQ8SPYvdu5G7szxIZV
4/AZvThoPDYiC3FR/+eaLdjtbPdNxGMlgjzGPYTKMxrq7PXxp1iRCcDFKSRR6a82
kq7qajs20DW8IeV1j+JCeRolX9/WmU97tLaV1+CFwQ3AjXRjDbyMorG+4XhsyVF/
cTbPIRY2rLfXGBfPwXABqBBWxd/4HvBlrisjjAMF+fg1poCENOIDoD8DieILRCm4
jw==
-----END CERTIFICATE-----
  `)
	keyPEMBlock := []byte(`
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAqBwPyUUMA/MpeVTF5v3gjPcD1UkFahekST05zKcvxaDP/oQC
N5LduKboR0dVMPxeuvCcqSIXMxAJVHrVwET4LKWHLyzFWnPv0DLfRPdZI+fU+aWS
EullFCGUkQuqjBpLfBx7GOGqiVw9mym35MLHTWlZwJ5vaex8VTnCjwAW7am+BTOm
dUeFSbfyEzTCk6qDjzh3cPrOXTB//0FBejcCO2ZniXCOy0cyfdnZDIx7IS5CiFgd
DfreGfgSR1mv8eoebt0u6YRGQB3Nycs0i56/Gg6UMdtRKaNngAZ/5D0zG9CYwN+W
97thIz7PTCdZjOQrxuNehQj2OXTDR4Zf304q9QIDAQABAoIBAB4rEwYqlvJqg8nb
VbyTWOXTOmPfO9KDNZ9TFnlMk30i09C3/fHdMF7/zPVlrrsgvxtLLMIJdSJbwWDg
vlVHy0Wv2uezYCNQZPv29SxaOyv/Ya//b4xnSBVpxVCWSF/mJB+8uLaJYOJPpFqh
DPhHoB6bRlkT1airoNBmkiy5dmPl5LJvy7+tzqqNZ8rq2oUu3+qKgpmCTuDRnMQr
XbvxN1YjzLDmOFnY6c6eRno0MaF1NVjd202nycyTtVsclprYsO7ZXXPOYzIjrI1a
OGAH9Yu90kN/KOcsbhqfOL06x5IZFFezOT3pm9aOJCUEBRLzyUl2GLJZvacAO/L7
oMqvl+0CgYEA3NV12PwEy1jeaQkd3Bir+GqIxYe/PcLQn+KuTmrErWWYmQX7bHJX
3VIH/hEPp3lGJcod8HfhVYntb/STmVpXFg6QCKP49qLaKD+qm6Wh+DzsPf/SazGQ
uMA3+9ObQ0BDHTrSbgb4RaG+filbwJ9YBUvK8CtgdnRDXnMcwUirH5sCgYEAwuE9
SX2qztREr6ABaCqk7V46hVqYsmHmjlaaAQcnjmEFk7pP3SYrOIlDWIBcEj5A/ZfT
eXSp8ld1W8JUg9SaJ8CR1tGjn+EG/TdED7fbLZD8VOd+7mhGHJVrZ00W8Co/Wgd8
kF+lUGVQSLVvXocuVHgEmRcxyFi7Ld0bVDnbsK8CgYEAwrPZoaQhvf/uqIEHOKTw
CqgzSqVy8cswEafUswLjwVXQAysJEAaIfXPz5Ae625fLR0o6t2ea3sYq+AiVkiHa
onHYgCXCPgI7gj0P+QdCFRHx4IALT8N1q86eDYP2YoboJX9VRPkUMKB4yddBNEXJ
X3IBzVsRQ58iPsYTVj7x0X0CgYEAsPeLCQaWKpX1/aoGPQqklG0CJYD8sthWXqFj
3lUZ5aBTSTBiP8febcuwHVkKwwJHUEIkJuH7RfeHuhjBWKmih0DG7tWWiaP2DdG2
+7MQ1NMZYRyLVoHYUTKawsbtcpBa0S2FPzGr1FL8Udp41NVbDBekzUSTz4RMDb0A
iT61Mj8CgYEAtSEcCNHxWDi6USqOUAlRxMP2iXNy0pRWKAWzRPklRWFXljw2MNf5
1n7WUHAEqLTZ4AvMyNJkMHCa3J/1gm/LH8ytVf+m63a/3+aKLTal4V2a5pjEJkWa
m7nMXmArpnt0hllKTipaLxSXfPKlb5ZO3Fs9JOmxqOZRJpaHleUwFuw=
-----END RSA PRIVATE KEY-----
  `)
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
