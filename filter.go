package keyless

type GetCertFilter struct {
	GetCert GetCertFunc
	Filter  func(op *Operation) (ok bool)
}

func (f *GetCertFilter) GetCertificate(op *Operation) (*Certificate, error) {
	if op.SKI.Valid() || f.Filter(op) {
		return f.GetCert(op)
	}

	return nil, ErrorCertNotFound
}
