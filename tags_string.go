// Code generated by "stringer -type=Tag -output=tags_string.go"; DO NOT EDIT

package keyless

import "fmt"

const (
	_Tag_name_0 = "TagDigestTagSNITagClientIPTagSKITagServerIPTagSigAlgs"
	_Tag_name_1 = "TagOpcodeTagPayload"
	_Tag_name_2 = "TagPadding"
	_Tag_name_3 = "TagOCSPResponseTagSignedCertTimestamps"
	_Tag_name_4 = "TagECDSACipher"
)

var (
	_Tag_index_0 = [...]uint8{0, 9, 15, 26, 32, 43, 53}
	_Tag_index_1 = [...]uint8{0, 9, 19}
	_Tag_index_2 = [...]uint8{0, 10}
	_Tag_index_3 = [...]uint8{0, 15, 38}
	_Tag_index_4 = [...]uint8{0, 14}
)

func (i Tag) String() string {
	switch {
	case 1 <= i && i <= 6:
		i -= 1
		return _Tag_name_0[_Tag_index_0[i]:_Tag_index_0[i+1]]
	case 17 <= i && i <= 18:
		i -= 17
		return _Tag_name_1[_Tag_index_1[i]:_Tag_index_1[i+1]]
	case i == 32:
		return _Tag_name_2
	case 257 <= i && i <= 258:
		i -= 257
		return _Tag_name_3[_Tag_index_3[i]:_Tag_index_3[i+1]]
	case i == 49153:
		return _Tag_name_4
	default:
		return fmt.Sprintf("Tag(%d)", i)
	}
}
