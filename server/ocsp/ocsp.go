package ocsp

import (
	"bytes"
	"crypto/sha1"
	"io/ioutil"
	"net/http"
	"sync"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/tmthrgd/keyless"
	"github.com/tmthrgd/keyless/server"
)

type cahceID [sha1.Size]byte

type cacheEntry struct {
	Bytes    []byte
	Response *ocsp.Response
}

func (e *cacheEntry) Valid() bool {
	return e.Response == nil || time.Now().Before(e.Response.NextUpdate)
}

type Requester struct {
	sync.RWMutex
	cache map[cahceID]*cacheEntry
	once  map[cahceID]*sync.Once

	getCertificate server.GetCertFunc

	RequestOptions *ocsp.RequestOptions
}

func NewRequester(getCertificate server.GetCertFunc) *Requester {
	return &Requester{
		cache: make(map[cahceID]*cacheEntry),
		once:  make(map[cahceID]*sync.Once),

		getCertificate: getCertificate,
	}
}

func (or *Requester) GetCertificate(op *keyless.Operation) (cert *keyless.Certificate, err error) {
	if cert, err = or.getCertificate(op); err != nil || cert.OCSP != nil {
		return
	}

	id := sha1.Sum(cert.Payload)

	or.RLock()
	entry, ok := or.cache[id]
	or.RUnlock()

	if ok && entry.Valid() {
		cert.OCSP = entry.Bytes
		return
	}

	or.Lock()

	if entry, ok = or.cache[id]; ok && entry.Valid() {
		or.Unlock()

		cert.OCSP = entry.Bytes
		return
	}

	once, ok := or.once[id]
	if !ok {
		once = new(sync.Once)
		or.once[id] = once
	}

	or.Unlock()

	once.Do(func() {
		entry, err = or.requestOCSP(cert)

		or.Lock()
		or.cache[id] = entry
		or.Unlock()
	})
	if err != nil {
		return
	}

	if entry == nil {
		or.RLock()
		entry, _ = or.cache[id]
		or.RUnlock()
	}

	if entry != nil {
		cert.OCSP = entry.Bytes
	}

	return
}

func (or *Requester) requestOCSP(cert *keyless.Certificate) (entry *cacheEntry, err error) {
	entry = new(cacheEntry)

	x509s, err := cert.PayloadToX509s()
	if err != nil || len(x509s) < 2 {
		if err == keyless.ErrorFormat {
			err = keyless.ErrorInternal
		}

		return
	}

	ocspReq, err := ocsp.CreateRequest(x509s[0], x509s[1], or.RequestOptions)
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
