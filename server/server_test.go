// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package server

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/asn1"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ed25519"

	"github.com/tmthrgd/keyless"
)

var (
	rsaPSSKeySKI = keyless.SKI{0xf8, 0x8c, 0x1f, 0xd9, 0x90, 0xbb, 0x15, 0x9e, 0x26, 0xa2, 0xbb, 0x3c, 0x59, 0x64, 0x9f, 0xf5, 0x69, 0xea, 0xda, 0xad}
	ecdsaKeySKI  = keyless.SKI{0x00, 0x82, 0x62, 0x7c, 0x92, 0xe8, 0xc4, 0x6c, 0x8c, 0x05, 0x71, 0x3f, 0x0a, 0x70, 0xeb, 0x2e, 0x09, 0xf9, 0x63, 0xc1}
)

func fromHexChar(c byte) (b byte, skip bool, ok bool) {
	switch {
	case '0' <= c && c <= '9':
		return c - '0', false, true
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10, false, true
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10, false, true
	case c == ' ' || c == '\t':
		return 0, true, false
	}

	return 0, false, false
}

func parseTestCase(path string) (request, response []byte, err error) {
	f, err := os.Open(path)
	if err != nil {
		return
	}

	defer f.Close()

	var req, resp bytes.Buffer
	var isResp bool

	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		data := scanner.Bytes()

		if bytes.Equal(data, []byte{'-', '-', '-'}) {
			if isResp {
				err = errors.New("invalid format: already in response")
				return
			}

			isResp = true
			continue
		}

		if i := bytes.IndexByte(data, ';'); i != -1 {
			data = data[:i]
		}

		for i := 0; i < len(data); i++ {
			a, skip, ok := fromHexChar(data[i])
			if skip {
				continue
			} else if !ok {
				err = fmt.Errorf("invalid format: expected hex or space, got %c", data[i])
				return
			}

			if i++; i == len(data) {
				err = errors.New("invalid format: expected hex, got EOF")
				return
			}

			b, _, ok := fromHexChar(data[i])
			if !ok {
				err = fmt.Errorf("invalid format: expected hex, got %c", data[i])
				return
			}

			if isResp {
				resp.WriteByte((a << 4) | b)
			} else {
				req.WriteByte((a << 4) | b)
			}
		}
	}

	if err = scanner.Err(); err != nil {
		return
	}

	return req.Bytes(), resp.Bytes(), nil
}

type loggerWriter struct {
	testing.TB
}

func (w *loggerWriter) Write(p []byte) (n int, err error) {
	n = len(p)

	p = bytes.TrimRight(p, "\r\n")
	w.Log(string(p))
	return
}

func isAuthorised(pub ed25519.PublicKey, op *keyless.Operation) error {
	if bytes.Equal(op.Authorisation, []byte("deny")) {
		return keyless.ErrorNotAuthorised
	}

	return nil
}

func TestRunner(t *testing.T) {
	runner(t)
}

func BenchmarkRunner(b *testing.B) {
	runner(b)
}

func runner(tb testing.TB) {
	logger := &loggerWriter{tb}

	keys := NewKeyLoader()
	certs := NewCertLoader()

	if err := keys.LoadFromDir("../test-data/certificate"); err != nil {
		tb.Fatal(err)
	}

	if err := certs.LoadFromDir("../test-data/certificate"); err != nil {
		tb.Fatal(err)
	}

	handler := &RequestHandler{
		GetCert: certs.GetCertificate,
		GetKey:  keys.GetKey,

		IsAuthorised: isAuthorised,

		ErrorLog: log.New(logger, "", log.Lshortfile),

		NoSignature: true,
		SkipPadding: true,
	}

	if err := filepath.Walk("../test-data/transcript", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() || !strings.HasSuffix(info.Name(), ".test") {
			return nil
		}

		rel, err := filepath.Rel("../test-data/transcript", path)
		if err != nil {
			rel = path
		}

		if b, ok := tb.(*testing.B); ok {
			b.Run(rel, func(bb *testing.B) {
				logger.TB = bb
				defer func() {
					logger.TB = tb
				}()

				runBenchmarkCase(bb, path, handler)
			})
		} else {
			tb.(*testing.T).Run(rel, func(tt *testing.T) {
				logger.TB = tt
				defer func() {
					logger.TB = tb
				}()

				runTestCase(tt, path, handler)
			})
		}

		return nil
	}); err != nil {
		tb.Error(err)
	}
}

func runTestCase(t *testing.T, path string, handler *RequestHandler) {
	req, resp, err := parseTestCase(path)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("-> %x", req)
	t.Logf("<- %x", resp)

	got, err := handler.Handle(req)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got, resp) {
		t.Error("invalid response")
		t.Logf("expected: %02x", resp)
		t.Logf("got:      %02x", got)
	}
}

func runBenchmarkCase(b *testing.B, path string, handler *RequestHandler) {
	req, _, err := parseTestCase(path)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if _, err := handler.Handle(append([]byte(nil), req...)); err != nil {
			b.Fatal(err)
		}
	}
}

func TestSigning(t *testing.T) {
	signing(t)
}

func BenchmarkSigning(b *testing.B) {
	signing(b)
}

func signing(tb testing.TB) {
	logger := &loggerWriter{tb}

	keys := NewKeyLoader()
	certs := NewCertLoader()

	if err := keys.LoadFromDir("../test-data/certificate"); err != nil {
		tb.Fatal(err)
	}

	if err := certs.LoadFromDir("../test-data/certificate"); err != nil {
		tb.Fatal(err)
	}

	handler := &RequestHandler{
		GetCert: certs.GetCertificate,
		GetKey:  keys.GetKey,

		IsAuthorised: isAuthorised,

		ErrorLog: log.New(logger, "", log.Lshortfile),

		NoSignature: true,
		SkipPadding: true,
	}

	for j, idx := 0, 0; j <= 1; j++ {
		for _, h := range []crypto.Hash{crypto.MD5SHA1, crypto.SHA1, crypto.SHA224, crypto.SHA256, crypto.SHA384, crypto.SHA512} {
			/* The RSA private key is only 1024-bits, it is thus too small for a SHA512 RSA-PSS signature. Skip it. */
			if j == 1 && (h != crypto.SHA256 && h != crypto.SHA384) {
				continue
			}

			name := fmt.Sprintf("%02d", idx)

			if j == 1 {
				name += "-pss"
			} else {
				name += "-ecdsa"
			}

			switch h {
			case crypto.MD5SHA1:
				name += "-md5-sha1"
			case crypto.SHA1:
				name += "-sha1"
			case crypto.SHA224:
				name += "-sha224"
			case crypto.SHA256:
				name += "-sha256"
			case crypto.SHA384:
				name += "-sha384"
			case crypto.SHA512:
				name += "-sha512"
			}

			if b, ok := tb.(*testing.B); ok {
				b.Run(name, func(bb *testing.B) {
					logger.TB = bb
					defer func() {
						logger.TB = tb
					}()

					runBenchmarkSigningCase(bb, byte(idx), h, j == 1, handler)
				})
			} else {
				var ski keyless.SKI

				if j == 1 {
					ski = rsaPSSKeySKI
				} else {
					ski = ecdsaKeySKI
				}

				priv, err := keys.GetKey(ski)
				if err != nil {
					tb.Fatal(err)
				}

				tb.(*testing.T).Run(name, func(tt *testing.T) {
					logger.TB = tt
					defer func() {
						logger.TB = tb
					}()

					runTestSigningCase(tt, byte(idx), h, j == 1, priv.(crypto.Signer).Public(), handler)
				})
			}

			idx++
		}
	}
}

func generateSigningRequest(idx byte, h crypto.Hash, ecdsaOrPSS bool) ([]byte, []byte, error) {
	op := &keyless.Operation{SkipPadding: true}

	switch h {
	case crypto.MD5SHA1:
		op.Opcode = keyless.OpRSASignMD5SHA1
	case crypto.SHA1:
		op.Opcode = keyless.OpRSASignSHA1
	case crypto.SHA224:
		op.Opcode = keyless.OpRSASignSHA224
	case crypto.SHA256:
		op.Opcode = keyless.OpRSASignSHA256
	case crypto.SHA384:
		op.Opcode = keyless.OpRSASignSHA384
	case crypto.SHA512:
		op.Opcode = keyless.OpRSASignSHA512
	default:
		return nil, nil, errors.New("invalid hash")
	}

	if ecdsaOrPSS {
		op.Opcode |= keyless.Op(0x0030) // RSA-PSS
	} else {
		op.Opcode |= keyless.Op(0x0010) // ECDSA
	}

	if ecdsaOrPSS {
		op.SKI = rsaPSSKeySKI
	} else {
		op.SKI = ecdsaKeySKI
	}

	if h == crypto.MD5SHA1 {
		h1, h2 := crypto.MD5.New(), crypto.SHA1.New()
		h1.Write([]byte("test"))
		h2.Write([]byte("test"))
		op.Payload = bytes.Join([][]byte{h1.Sum(nil), h2.Sum(nil)}, nil)
	} else {
		hh := h.New()
		hh.Write([]byte("test"))
		op.Payload = hh.Sum(nil)
	}

	hdr := &keyless.Header{
		ID: uint32(idx),

		NoSignature: true,
	}
	return op.Payload, hdr.Marshal(op, nil, nil), nil
}

func runTestSigningCase(t *testing.T, idx byte, h crypto.Hash, ecdsaOrPSS bool, pub crypto.PublicKey, handler *RequestHandler) {
	hash, req, err := generateSigningRequest(idx, h, ecdsaOrPSS)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("-> %x", req)
	t.Logf("<- 020000xx000000%02x0011000200f0001200xx...", idx)

	got, err := handler.Handle(req)
	if err != nil {
		t.Fatal(err)
	}

	hdr := &keyless.Header{NoSignature: true}

	body, err := hdr.Unmarshal(got)
	if err != nil {
		t.Fatal(err)
	}

	switch {
	case hdr.Major != keyless.VersionMajor:
		t.Fatal(keyless.ErrorVersionMismatch)
	case int(hdr.Length) != len(body):
		t.Fatal(keyless.WrappedError{keyless.ErrorFormat,
			errors.New("invalid header length")})
	}

	op := new(keyless.Operation)
	if err = op.Unmarshal(body); err != nil {
		t.Fatal(err)
	}

	var valid bool

	if ecdsaOrPSS {
		valid = rsa.VerifyPSS(pub.(*rsa.PublicKey), h, hash, op.Payload, &rsa.PSSOptions{rsa.PSSSaltLengthEqualsHash, h}) == nil
	} else {
		var sig struct {
			R, S *big.Int
		}

		if _, err := asn1.Unmarshal(op.Payload, &sig); err != nil {
			t.Fatal(err)
		}

		valid = ecdsa.Verify(pub.(*ecdsa.PublicKey), hash, sig.R, sig.S)
	}

	if !valid {
		t.Fatal("invalid signature")
	}
}

func runBenchmarkSigningCase(b *testing.B, idx byte, h crypto.Hash, ecdsaOrPSS bool, handler *RequestHandler) {
	_, req, err := generateSigningRequest(idx, h, ecdsaOrPSS)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if _, err := handler.Handle(append([]byte(nil), req...)); err != nil {
			b.Fatal(err)
		}
	}
}
