package keyless

type AnyIsAuthorised []IsAuthorisedFunc

func (any AnyIsAuthorised) IsAuthorised(op *Operation) error {
	for _, fn := range any {
		if err := fn(op); GetErrorCode(err) != ErrorNotAuthorised {
			return err
		}
	}

	return ErrorNotAuthorised
}

type AllIsAuthorised []IsAuthorisedFunc

func (all AllIsAuthorised) IsAuthorised(op *Operation) error {
	for _, fn := range all {
		if err := fn(op); err != nil {
			return err
		}
	}

	return nil
}
