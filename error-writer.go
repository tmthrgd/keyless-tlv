package keyless

import "io"

type errWriter struct {
	w   io.Writer
	err error
}

func (w *errWriter) Write(p []byte) (n int, err error) {
	if w.err != nil {
		return 0, w.err
	}

	n, err = w.w.Write(p)
	w.err = err
	return
}
