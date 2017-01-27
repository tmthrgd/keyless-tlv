package keyless

const (
	VersionMajor = 2
	VersionMinor = 0
)

const maxUint16 = int(^uint16(0))

type IsAuthorisedFunc func(op *Operation) error
