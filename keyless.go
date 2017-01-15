package keyless

const (
	VersionMajor = 2
	VersionMinor = 0
)

type IsAuthorisedFunc func(op *Operation) error
