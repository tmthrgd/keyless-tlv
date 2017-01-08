package keyless

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"math/rand"
	"testing"
)

func TestCertificatePayload(t *testing.T) {
	cert := new(Certificate)
	cert.SetPayloadFromDER([][]byte{[]byte("test")})

	if !bytes.Equal(cert.Payload, []byte("\x00\x04test")) {
		t.Fatal("(*Certificate).SetPayloadFromDER format invalid")
	}

	cert.SetPayloadFromX509s([]*x509.Certificate{&x509.Certificate{Raw: []byte("test")}})

	if !bytes.Equal(cert.Payload, []byte("\x00\x04test")) {
		t.Fatal("(*Certificate).SetPayloadFromDER format invalid")
	}
}

func TestCertificateDERPayload(t *testing.T) {
	ders := make([][]byte, 10)

	for i := range make([]struct{}, len(ders)) {
		ders[i] = make([]byte, rand.Intn(128))
		rand.Read(ders[i])
	}

	cert := new(Certificate)
	cert.SetPayloadFromDER(ders)

	ders2, err := cert.PayloadToDER()
	if err != nil {
		t.Fatal(err)
	}

	if len(ders) != len(ders2) {
		t.Fatal("different number of certificates returned")
	}

	for i, der := range ders {
		if !bytes.Equal(der, ders2[i]) {
			t.Errorf("certificate #%d differs from original", i)
		}
	}
}

const md5cert = `
-----BEGIN CERTIFICATE-----
MIIB4TCCAUoCCQCfmw3vMgPS5TANBgkqhkiG9w0BAQQFADA1MQswCQYDVQQGEwJB
VTETMBEGA1UECBMKU29tZS1TdGF0ZTERMA8GA1UEChMITUQ1IEluYy4wHhcNMTUx
MjAzMTkyOTMyWhcNMjkwODEyMTkyOTMyWjA1MQswCQYDVQQGEwJBVTETMBEGA1UE
CBMKU29tZS1TdGF0ZTERMA8GA1UEChMITUQ1IEluYy4wgZ8wDQYJKoZIhvcNAQEB
BQADgY0AMIGJAoGBANrq2nhLQj5mlXbpVX3QUPhfEm/vdEqPkoWtR/jRZIWm4WGf
Wpq/LKHJx2Pqwn+t117syN8l4U5unyAi1BJSXjBwPZNd7dXjcuJ+bRLV7FZ/iuvs
cfYyQQFTxan4TaJMd0x1HoNDbNbjHa02IyjjYE/r3mb/PIg+J2t5AZEh80lPAgMB
AAEwDQYJKoZIhvcNAQEEBQADgYEAjGzp3K3ey/YfKHohf33yHHWd695HQxDAP+wY
cs9/TAyLR+gJzJP7d18EcDDLJWVi7bhfa4EAD86di05azOh9kWSn4b3o9QYRGCSw
GNnI3Zk0cwNKA49hZntKKiy22DhRk7JAHF01d6Bu3KkHkmENrtJ+zj/+159WAnUa
qViorq4=
-----END CERTIFICATE-----
`

func TestCertificateX509Payload(t *testing.T) {
	pemBlock, _ := pem.Decode([]byte(md5cert))

	xCert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	cert := new(Certificate)
	cert.SetPayloadFromX509s([]*x509.Certificate{xCert})

	x509s, err := cert.PayloadToX509s()
	if err != nil {
		t.Fatal(err)
	}

	if len(x509s) != 1 {
		t.Fatal("different number of certificates returned")
	}

	if !xCert.Equal(x509s[0]) {
		t.Fatal("certificate differs from original")
	}
}
