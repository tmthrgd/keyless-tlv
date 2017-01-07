package keyless

import "io"

type errWriter struct {
	W   io.Writer
	Err error
}

func (w *errWriter) Write(p []byte) (n int, err error) {
	if w.Err != nil {
		return 0, w.Err
	}

	n, err = w.W.Write(p)
	w.Err = err
	return
}

type lenWriter struct {
	W io.Writer
	N int
}

func (w *lenWriter) Write(p []byte) (n int, err error) {
	n, err = w.W.Write(p)
	w.N += n
	return
}
