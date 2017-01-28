package keyless

const Version = 0x80 | 1

const maxUint16 = int(^uint16(0))

type IsAuthorisedFunc func(op *Operation) error
