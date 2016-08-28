// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"bytes"
	crand "crypto/rand"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var nameRand *rand.Rand

func init() {
	var seed [8]byte

	if _, err := crand.Read(seed[:]); err != nil {
		panic(err)
	}

	seedInt := int64(binary.LittleEndian.Uint64(seed[:]))
	nameRand = rand.New(rand.NewSource(seedInt))
}

var agentExe string

func TestMain(m *testing.M) {
	dir, err := ioutil.TempDir("", "go-test-agent")
	if err != nil {
		panic(err)
	}

	agentExe = dir + "/ip-blocker-agent"

	cmd := exec.Command("go", "build", "-o", agentExe, ".")
	cmd.Stderr = os.Stderr
	cmd.Run()

	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func testAddress() string {
	return fmt.Sprintf("127.%d.%d.%d:%d", nameRand.Intn(256), nameRand.Intn(256), nameRand.Intn(255-1)+1, nameRand.Intn(65536-49152)+49152)
}

func testCommand(addr string) *exec.Cmd {
	return exec.Command(agentExe, "-addr", addr, "-dir", "./test-data/ssl", "-pid", "", "-padding=false")
}

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
	addr := testAddress()
	cmd := testCommand(addr)

	logger := &loggerWriter{t}
	cmd.Stdout, cmd.Stderr = logger, logger

	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	time.Sleep(100 * time.Millisecond)

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

			runTestCase(tt, path, addr)
		})
		return nil
	}); err != nil {
		t.Error(err)
	}

	if err := cmd.Process.Kill(); err != nil {
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

func runTestCase(t *testing.T, path, addr string) {
	req, resp := parseTestCase(t, path)

	t.Logf("-> %x", req)
	t.Logf("<- %x", resp)

	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}

	n, err := conn.Write(req)
	if err != nil {
		t.Fatal(err)
	}

	n = 2 * 1024
	if n < len(resp) {
		n = len(resp) + 1024
	}

	got := make([]byte, n)

	if n, err = conn.Read(got); err != nil {
		t.Fatal(err)
	}

	got = got[:n]

	if !bytes.Equal(got, resp) {
		t.Error("invalid response")
		t.Logf("expected: %02x", resp)
		t.Logf("got:      %02x", got)
	}
}
