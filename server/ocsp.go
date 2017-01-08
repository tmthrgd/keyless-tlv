package server

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"sync"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/tmthrgd/keyless"
)

type ocspCacheEntry struct {
	Bytes    []byte
	Response *ocsp.Response
}

func (e *ocspCacheEntry) Valid() bool {
	return e.Response == nil || time.Now().Before(e.Response.NextUpdate)
}

type OCSPRequester struct {
	sync.RWMutex
	cache map[keyless.SKI]*ocspCacheEntry
	once  map[keyless.SKI]*sync.Once

	getCertificate GetCertFunc

	OCSPRequestOptions *ocsp.RequestOptions
}

func NewOCSPRequester(getCertificate GetCertFunc) *OCSPRequester {
	return &OCSPRequester{
		cache: make(map[keyless.SKI]*ocspCacheEntry),
		once:  make(map[keyless.SKI]*sync.Once),

		getCertificate: getCertificate,
	}
}

func (or *OCSPRequester) GetCertificate(op *keyless.Operation) (cert *keyless.Certificate, err error) {
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

func (or *OCSPRequester) requestOCSP(cert *keyless.Certificate) (entry *ocspCacheEntry, err error) {
	entry = new(ocspCacheEntry)

	x509s, err := cert.PayloadToX509s()
	if err != nil || len(x509s) < 2 {
		if err == keyless.ErrorFormat {
			err = keyless.ErrorInternal
		}

		return
	}

	ocspReq, err := ocsp.CreateRequest(x509s[0], x509s[1], or.OCSPRequestOptions)
	if err != nil {
		return
	}

	resp, err := http.Post(x509s[0].OCSPServer[0], "application/ocsp-request",
		bytes.NewReader(ocspReq))
	if err != nil {
		return
	}

	ocspRespBytes, err := ioutil.ReadAll(http.MaxBytesReader(nil, resp.Body, 1024*1024))

	resp.Body.Close()

	if err != nil {
		return
	}

	ocspResp, err := ocsp.ParseResponse(ocspRespBytes, x509s[1])
	if err != nil {
		return
	}

	if ocspResp.Certificate == nil {
		if err = ocspResp.CheckSignatureFrom(x509s[1]); err != nil {
			return
		}
	}

	entry.Bytes, entry.Response = ocspRespBytes, ocspResp
	return
}
