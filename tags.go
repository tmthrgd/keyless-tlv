package main

//go:generate stringer -type=Tag -output=tags_string.go

type Tag byte

const (
	TagDigest   Tag = 0x01 // [Deprecated]: SHA256 hash of RSA public key
	TagSNI      Tag = 0x02 // Server Name Identifier
	TagClientIP Tag = 0x03 // Client IP Address
	TagSKI      Tag = 0x04 // SHA1 hash of Subject Key Info
	TagServerIP Tag = 0x05 // Server IP Address
	TagSigAlgs  Tag = 0x06 // Signature Algorithms
	TagOpcode   Tag = 0x11 // Request operation code (see Op)
	TagPayload  Tag = 0x12 // Request/response payload
	TagPadding  Tag = 0x20 // Padding

	// The range [0xc0, 0xff) is reserved for private tags.
	TagECDSACipher Tag = 0xc0 // One iff ECDSA ciphers are supported
)
