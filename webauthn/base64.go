package webauthn

import (
	"bytes"
	"encoding/base64"
	"reflect"
)

// URLEncodedBase64 is a custom type used in place of []byte for webauthn,
// as the specification require a json RawURLEncoding instead of the default StdEncoding
// implemented by the json package.
type URLEncodedBase64 []byte

func (dest *URLEncodedBase64) UnmarshalJSON(data []byte) error {
	data = bytes.Trim(data, "\"")
	out := make([]byte, base64.RawURLEncoding.DecodedLen(len(data)))
	n, err := base64.RawURLEncoding.Decode(out, data)
	if err != nil {
		return err
	}

	v := reflect.ValueOf(dest).Elem()
	v.SetBytes(out[:n])
	return nil
}

func (data URLEncodedBase64) MarshalJSON() ([]byte, error) {
	if data == nil {
		return []byte("null"), nil
	}
	return []byte(`"` + base64.RawURLEncoding.EncodeToString(data) + `"`), nil
}
