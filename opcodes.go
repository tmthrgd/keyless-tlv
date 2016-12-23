package main

//go:generate stringer -type=Op -output=opcodes_string.go

type Op uint16

const (
	// The range [0x0000, 0x0100) is for opcodes taken from Cloudflare's upstream.

	// Decrypt data using RSA with or without padding
	OpRSADecrypt    Op = 0x0001
	OpRSADecryptRaw Op = 0x0008

	// Sign data using RSA
	OpRSASignMD5SHA1 Op = 0x0002
	OpRSASignSHA1    Op = 0x0003
	OpRSASignSHA224  Op = 0x0004
	OpRSASignSHA256  Op = 0x0005
	OpRSASignSHA384  Op = 0x0006
	OpRSASignSHA512  Op = 0x0007

	// Sign data using RSA-PSS
	OpRSAPSSSignSHA256 Op = 0x0035
	OpRSAPSSSignSHA384 Op = 0x0036
	OpRSAPSSSignSHA512 Op = 0x0037

	// Sign data using ECDSA
	OpECDSASignMD5SHA1 Op = 0x0012
	OpECDSASignSHA1    Op = 0x0013
	OpECDSASignSHA224  Op = 0x0014
	OpECDSASignSHA256  Op = 0x0015
	OpECDSASignSHA384  Op = 0x0016
	OpECDSASignSHA512  Op = 0x0017

	// Request a certificate and chain
	OpGetCertificate Op = 0x0020

	// [Deprecated]: A test message
	OpPing Op = 0x00F1
	OpPong Op = 0x00F2

	// [Deprecated]: A verification message
	OpActivate Op = 0x00F3

	// Response
	OpResponse Op = 0x00F0
	OpError    Op = 0x00FF

	// The range [0x0100, 0xc000) is for opcodes from our protocol version.
	OpEd25519Sign Op = 0x0101 // Sign data using Ed25519

	// The range [0xc000, 0xffff) is reserved for private opcodes.
)
