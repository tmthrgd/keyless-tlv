package server

import (
	"fmt"
	"sync/atomic"
)

type RequestHandlerStats struct {
	requests uint64

	versionErrorss, formatErrors, unauthorised, unmarshal, process uint64
	unexpectedOps, badOps                                          uint64

	panics uint64

	pings, certRequests, decrypts, signs, rsaOps, ecdsaOps, ed25519Ops uint64
}

func (s *RequestHandlerStats) Requests() uint64            { return atomic.LoadUint64(&s.requests) }
func (s *RequestHandlerStats) VersionMismatches() uint64   { return atomic.LoadUint64(&s.versionErrorss) }
func (s *RequestHandlerStats) FormatErrors() uint64        { return atomic.LoadUint64(&s.formatErrors) }
func (s *RequestHandlerStats) UnauthorisedErrors() uint64  { return atomic.LoadUint64(&s.unauthorised) }
func (s *RequestHandlerStats) UnmarshallingErrors() uint64 { return atomic.LoadUint64(&s.unmarshal) }
func (s *RequestHandlerStats) ProcessingErrors() uint64    { return atomic.LoadUint64(&s.process) }
func (s *RequestHandlerStats) UnexpectedOpcodes() uint64   { return atomic.LoadUint64(&s.unexpectedOps) }
func (s *RequestHandlerStats) BadOpcodes() uint64          { return atomic.LoadUint64(&s.badOps) }
func (s *RequestHandlerStats) Panics() uint64              { return atomic.LoadUint64(&s.panics) }
func (s *RequestHandlerStats) Pings() uint64               { return atomic.LoadUint64(&s.pings) }
func (s *RequestHandlerStats) CertificateRequests() uint64 { return atomic.LoadUint64(&s.certRequests) }
func (s *RequestHandlerStats) Decryptions() uint64         { return atomic.LoadUint64(&s.decrypts) }
func (s *RequestHandlerStats) Signings() uint64            { return atomic.LoadUint64(&s.signs) }
func (s *RequestHandlerStats) RSAOperations() uint64       { return atomic.LoadUint64(&s.rsaOps) }
func (s *RequestHandlerStats) ECDSAOperations() uint64     { return atomic.LoadUint64(&s.ecdsaOps) }
func (s *RequestHandlerStats) ED25519Operations() uint64   { return atomic.LoadUint64(&s.ed25519Ops) }

func (s *RequestHandlerStats) String() string {
	return fmt.Sprintf(`Requests:              %d
Errors:
 Version Mismatches:   %d
 Format:               %d
 Unauthorised:         %d
 Unmarshalling:        %d
 Processing:           %d
 Unexpected Opcodes:   %d
 Bad Opcodes:          %d
Panics:                %d
Operations:
 Pings:                %d
 Certificate Requests: %d
 Decryptions:          %d
 Signings:             %d
 RSA:                  %d
 ECDSA:                %d
 ED25519:              %d`,
		s.Requests(),

		s.VersionMismatches(), s.FormatErrors(), s.UnauthorisedErrors(),
		s.UnmarshallingErrors(), s.ProcessingErrors(),
		s.UnexpectedOpcodes(), s.BadOpcodes(),

		s.Panics(),

		s.Pings(), s.CertificateRequests(), s.Decryptions(),
		s.Signings(), s.RSAOperations(), s.ECDSAOperations(),
		s.ED25519Operations())
}

func (s *RequestHandlerStats) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`{ requests: "%d", `+
		`errors: { version_mismatches: "%d", format: "%d", unauthorised: "%d", `+
		`unmarshalling: "%d", processing: "%d", `+
		`unexpected_opcodes: "%d", bad_opcodes: "%d", }, `+
		`panics: "%d", `+
		`operations: { pings: "%d", certificate_requests: "%d", decryptions: "%d", `+
		`signings: "%d", rsa: "%d", ecdsa: "%d", ed25519: "%d" } }`,
		s.Requests(),

		s.VersionMismatches(), s.FormatErrors(), s.UnauthorisedErrors(),
		s.UnmarshallingErrors(), s.ProcessingErrors(),
		s.UnexpectedOpcodes(), s.BadOpcodes(),

		s.Panics(),

		s.Pings(), s.CertificateRequests(), s.Decryptions(),
		s.Signings(), s.RSAOperations(), s.ECDSAOperations(),
		s.ED25519Operations())), nil
}

type SelfSignerStats struct {
	issued uint64
}

func (s *SelfSignerStats) CertificatesIssued() uint64 { return atomic.LoadUint64(&s.issued) }

func (s *SelfSignerStats) String() string {
	return fmt.Sprintf("Certificates Issued: %d", s.CertificatesIssued())
}

func (s *SelfSignerStats) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`{ issued: "%d" }`, s.CertificatesIssued())), nil
}
