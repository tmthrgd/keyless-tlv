package keyless

import (
	"bytes"
	"crypto/x509"
	"encoding/binary"
	"io/ioutil"
	"net/http"
	"sync"
	"time"

	"golang.org/x/crypto/ocsp"
)

type ocspCacheEntry struct {
	Bytes    []byte
	Response *ocsp.Response
	None     bool
}

func (e *ocspCacheEntry) Valid() bool {
	return e.None || time.Now().Before(e.Response.NextUpdate)
}

type OCSPRequester struct {
	sync.RWMutex
	cache map[SKI]*ocspCacheEntry
	once  map[SKI]*sync.Once

	getCertificate GetCertFunc

	OCSPRequestOptions *ocsp.RequestOptions
}

func NewOCSPRequester(getCertificate GetCertFunc) *OCSPRequester {
	return &OCSPRequester{
		cache: make(map[SKI]*ocspCacheEntry),
		once:  make(map[SKI]*sync.Once),

		getCertificate: getCertificate,
	}
}

func (or *OCSPRequester) GetCertificate(op *Operation) (cert *Certificate, err error) {
	if cert, err = or.getCertificate(op); err != nil || cert.OCSP != nil {
		return
	}

	or.RLock()
	entry, ok := or.cache[cert.SKI]
	or.RUnlock()

	if ok && entry.Valid() {
		cert.OCSP = entry.Bytes
		return
	}

	or.Lock()

	if entry, ok = or.cache[cert.SKI]; ok && entry.Valid() {
		or.Unlock()

		cert.OCSP = entry.Bytes
		return
	}

	once, ok := or.once[cert.SKI]
	if !ok {
		once = new(sync.Once)
		or.once[cert.SKI] = once
	}

	or.Unlock()

	once.Do(func() {
		entry, err = or.requestOCSP(cert)

		or.Lock()
		or.cache[cert.SKI] = entry
		or.Unlock()
	})
	if err != nil {
		return
	}

	if entry == nil {
		or.RLock()
		entry, _ = or.cache[cert.SKI]
		or.RUnlock()
	}

	if entry != nil {
		cert.OCSP = entry.Bytes
	}

	return
}

func (or *OCSPRequester) requestOCSP(cert *Certificate) (entry *ocspCacheEntry, err error) {
	entry = &ocspCacheEntry{None: true}

	switch len(cert.Payload) {
	case 0:
		return
	case 1:
		err = ErrorInternal
		return
	}

	l, p := int(binary.BigEndian.Uint16(cert.Payload)), cert.Payload[2:]

	switch {
	case len(p) == l:
		return
	case len(p) < l+2:
		err = ErrorInternal
		return
	}

	issuedBytes, p := p[:l], p[l:]
	l, p = int(binary.BigEndian.Uint16(p)), p[2:]

	if len(p) < l {
		err = ErrorInternal
		return
	}

	issuerBytes := p[:l]

	issuedCert, err := x509.ParseCertificate(issuedBytes)
	if err != nil || len(issuedCert.OCSPServer) == 0 {
		return
	}

	issuerCert, err := x509.ParseCertificate(issuerBytes)
	if err != nil {
		return
	}

	ocspReq, err := ocsp.CreateRequest(issuedCert, issuerCert, or.OCSPRequestOptions)
	if err != nil {
		return
	}

	resp, err := http.Post(issuedCert.OCSPServer[0], "application/ocsp-request",
		bytes.NewReader(ocspReq))
	if err != nil {
		return
	}

	defer resp.Body.Close()

	entry.Bytes, err = ioutil.ReadAll(http.MaxBytesReader(nil, resp.Body, 1024*1024))
	if err != nil {
		return
	}

	entry.Response, err = ocsp.ParseResponse(entry.Bytes, issuerCert)

	if err == nil && entry.Response.Certificate == nil {
		err = entry.Response.CheckSignatureFrom(issuerCert)
	}

	entry.None = err != nil
	return
}
