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
	SCT     []byte
}

func (cert *Certificate) SetPayloadFromDER(ders [][]byte) {
	var b bytes.Buffer

	for _, der := range ders {
		if len(der) > maxUint16 {
			panic("certificate too large")
		}

		b.Grow(2 + len(der))

		binary.Write(&b, binary.BigEndian, uint16(len(der)))
		b.Write(der)
	}

	cert.Payload = b.Bytes()
}

func (cert *Certificate) SetPayloadFromX509s(x509s []*x509.Certificate) {
	var b bytes.Buffer

	for _, x509 := range x509s {
		if len(x509.Raw) > maxUint16 {
			panic("certificate too large")
		}

		b.Grow(2 + len(x509.Raw))

		binary.Write(&b, binary.BigEndian, uint16(len(x509.Raw)))
		b.Write(x509.Raw)
	}

	cert.Payload = b.Bytes()
}

func (cert *Certificate) PayloadToDER() ([][]byte, error) {
	ders := make([][]byte, 0, 4)
	payload := cert.Payload

	for len(payload) >= 2 {
		l := binary.BigEndian.Uint16(payload)
		if int(l) > len(payload)-2 {
			return nil, ErrorFormat
		}

		ders, payload = append(ders, payload[2:2+l:2+l]), payload[2+l:]
	}

	if len(payload) != 0 {
		return nil, ErrorFormat
	}

	return ders, nil
}

func (cert *Certificate) PayloadToX509s() ([]*x509.Certificate, error) {
	x509s := make([]*x509.Certificate, 0, 4)
	payload := cert.Payload

	for len(payload) >= 2 {
		l := binary.BigEndian.Uint16(payload)
		if int(l) > len(payload)-2 {
			return nil, ErrorFormat
		}

		cert, err := x509.ParseCertificate(payload[2 : 2+l])
		if err != nil {
			return nil, err
		}

		x509s, payload = append(x509s, cert), payload[2+l:]
	}

	if len(payload) != 0 {
		return nil, ErrorFormat
	}

	return x509s, nil
}
