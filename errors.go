package main

import "fmt"

type Error uint16

const (
	ErrorCryptoFailed     Error = 0x0001 // Cryptographic error
	ErrorKeyNotFound      Error = 0x0002 // Private key not found
	ErrorDiskRead         Error = 0x0003 // [Deprecated]: Disk read failure
	ErrorVersionMismatch  Error = 0x0004 // Client-Server version mismatch
	ErrorBadOpcode        Error = 0x0005 // Invalid/unsupported opcode
	ErrorUnexpectedOpcode Error = 0x0006 // Opcode sent at wrong time/direction
	ErrorFormat           Error = 0x0007 // Malformed message
	ErrorInternal         Error = 0x0008 // Other internal error
	ErrorCertNotFound     Error = 0x0009 // Certificate not found

	// The range [0xc000, 0xffff) is reserved for private errors.
	ErrorNotAuthorised Error = 0xc000 // The client was not authorised to perform that request.
)

func (e Error) Error() string {
	switch e {
	case 0:
		return "no error"
	case ErrorCryptoFailed:
		return "cryptography error"
	case ErrorKeyNotFound:
		return "key not found"
	case ErrorDiskRead:
		return "disk read failure"
	case ErrorVersionMismatch:
		return "version mismatch"
	case ErrorBadOpcode:
		return "bad opcode"
	case ErrorUnexpectedOpcode:
		return "unexpected opcode"
	case ErrorFormat:
		return "malformed message"
	case ErrorInternal:
		return "internal error"
	case ErrorCertNotFound:
		return "certificate not found"
	case ErrorNotAuthorised:
		return "client not authorised"
	default:
		return fmt.Sprintf("Error(%d)", e)
	}
}

type WrappedError struct {
	Code Error
	Err  error
}

func (e WrappedError) Error() string {
	return e.Code.Error() + ": " + e.Err.Error()
}
