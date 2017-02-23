package keyless

//go:generate stringer -type=Tag -output=tags_string.go

type Tag uint16

const (
	// The range [0x0000, 0x0100) is for tags taken from Cloudflare's upstream.
	TagDigest   Tag = 0x0001 // [Deprecated]: SHA256 hash of RSA public key
	TagSNI      Tag = 0x0002 // Server Name Identifier
	TagClientIP Tag = 0x0003 // Client IP Address
	TagSKI      Tag = 0x0004 // SHA1 hash of Subject Key Info
	TagServerIP Tag = 0x0005 // Server IP Address
	TagSigAlgs  Tag = 0x0006 // Signature Algorithms
	TagOpcode   Tag = 0x0011 // Request operation code (see Op)
	TagPayload  Tag = 0x0012 // Request/response payload
	TagPadding  Tag = 0x0020 // Padding

	// The range [0x0100, 0xc000) is for tags from our protocol version.
	TagOCSPResponse         Tag = 0x0101 // The OCSP response to staple
	TagSignedCertTimestamps Tag = 0x0102 // The SCT list to send to the client
	TagNonce                Tag = 0x0103 // The nonce used for OpSeal and OpUnseal
	TagAdditionalData       Tag = 0x0104 // The additional authenticated data for OpSeal and OpUnseal

	// The range [0xc000, 0xffff) is reserved for private tags.
	TagECDSACipher Tag = 0xc001 // One iff ECDSA ciphers are supported
)

// The number of supported tags. This is used to size the initial map capacity
// for seen tags in (*Operation).Unmarshal.
const numOfTags = 14
