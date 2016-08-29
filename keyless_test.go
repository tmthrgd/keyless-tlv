// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type loggerWriter struct {
	*testing.T
}

func (w *loggerWriter) Write(p []byte) (n int, err error) {
	n = len(p)

	p = bytes.TrimRight(p, "\r\n")
	w.Log(string(p))
	return
}

func TestRunner(t *testing.T) {
	keys := newKeyLoader()
	certs := newCertLoader()

	if err := keys.LoadFromDir("./test-data/ssl"); err != nil {
		t.Fatal(err)
	}

	if err := certs.LoadFromDir("./test-data/ssl"); err != nil {
		t.Fatal(err)
	}

	logger := &loggerWriter{t}
	log.SetOutput(logger)
	defer func() {
		log.SetOutput(os.Stderr)
	}()

	if err := filepath.Walk("./test-data/transcript", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() || !strings.HasSuffix(info.Name(), ".test") {
			return nil
		}

		rel, err := filepath.Rel("./test-data/transcript", path)
		if err != nil {
			rel = path
		}

		t.Run(rel, func(tt *testing.T) {
			logger.T = tt
			defer func() {
				logger.T = t
			}()

			runTestCase(tt, path, certs.GetCertificate, keys.GetKey)
		})
		return nil
	}); err != nil {
		t.Error(err)
	}
}

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

func parseTestCase(t *testing.T, path string) (request []byte, response []byte) {
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}

	var req, resp bytes.Buffer
	var isResp bool

	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		data := scanner.Bytes()

		if bytes.Equal(data, []byte{'-', '-', '-'}) {
			if isResp {
				t.Fatalf("invalid format: already in response")
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
				t.Fatalf("invalid format: expected hex or space, got %c", data[i])
			}

			i++

			b, _, ok := fromHexChar(data[i])
			if !ok {
				t.Fatalf("invalid format: expected hex, got %c", data[i])
			}

			if isResp {
				resp.WriteByte((a << 4) | b)
			} else {
				req.WriteByte((a << 4) | b)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}

	return req.Bytes(), resp.Bytes()
}

func runTestCase(t *testing.T, path string, getCert GetCertificate, getKey GetKey) {
	req, resp := parseTestCase(t, path)

	t.Logf("-> %x", req)
	t.Logf("<- %x", resp)

	got, err := handleRequest(req, getCert, getKey, false)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got, resp) {
		t.Error("invalid response")
		t.Logf("expected: %02x", resp)
		t.Logf("got:      %02x", got)
	}
}
