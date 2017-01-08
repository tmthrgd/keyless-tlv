package server

import "github.com/tmthrgd/keyless"

type GetCertFilter struct {
	GetCert GetCertFunc
	Filter  func(op *keyless.Operation) (ok bool)
}

func (f *GetCertFilter) GetCertificate(op *keyless.Operation) (*keyless.Certificate, error) {
	if op.SKI.Valid() || f.Filter(op) {
		return f.GetCert(op)
	}

	return nil, keyless.ErrorCertNotFound
}
