package keyless

import (
	"bytes"
	"crypto/x509"
	"encoding/binary"
)

type Certificate struct {
	SKI     SKI
	Payload []byte
	OCSP    []byte
}

func (cert *Certificate) SetPayloadFromDER(ders [][]byte) {
	var b bytes.Buffer

	for _, der := range ders {
		b.Grow(2 + len(der))

		binary.Write(&b, binary.BigEndian, uint16(len(der)))
		b.Write(der)
	}

	cert.Payload = b.Bytes()
	return
}

func (cert *Certificate) SetPayloadFromX509s(x509s []*x509.Certificate) {
	var b bytes.Buffer

	for _, x509 := range x509s {
		b.Grow(2 + len(x509.Raw))

		binary.Write(&b, binary.BigEndian, uint16(len(x509.Raw)))
		b.Write(x509.Raw)
	}

	cert.Payload = b.Bytes()
	return
}
