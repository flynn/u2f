package ctap2token

import (
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

// see https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#example-378a57e0
func TestEncodeCredentialRpEntity(t *testing.T) {
	e := CredentialRpEntity{
		Name: "Acme",
	}

	enc, err := cbor.CTAP2EncOptions().EncMode()
	require.NoError(t, err)

	got, err := enc.Marshal(e)
	require.NoError(t, err)

	require.Equal(
		t,
		"a1646e616d656441636d65",
		hex.EncodeToString(got),
	)
}

// see https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#example-8e31572a
func TestEncodeCredentialUserEntity(t *testing.T) {
	userID, err := base64.StdEncoding.DecodeString("MIIBkzCCATigAwIBAjCCAZMwggE4oAMCAQIwggGTMII=")
	require.NoError(t, err)

	e := CredentialUserEntity{
		ID:          userID,
		Icon:        "https://pics.example.com/00/p/aBjjjpqPb.png",
		Name:        "johnpsmith@example.com",
		DisplayName: "John P. Smith",
	}

	enc, err := cbor.CTAP2EncOptions().EncMode()
	require.NoError(t, err)

	got, err := enc.Marshal(e)
	require.NoError(t, err)

	require.Equal(
		t,
		"a462696458203082019330820138a0030201023082019330820138a0030201023082019330826469636f6e782b68747470733a2f2f706963732e6578616d706c652e636f6d2f30302f702f61426a6a6a707150622e706e67646e616d65766a6f686e70736d697468406578616d706c652e636f6d6b646973706c61794e616d656d4a6f686e20502e20536d697468",
		hex.EncodeToString(got),
	)
}

// see https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#example-23bb4dbc
func TestEncodeCredentialParameters(t *testing.T) {
	params := []CredentialParam{
		PublicKeyES256,
		PublicKeyRS256,
	}

	enc, err := cbor.CTAP2EncOptions().EncMode()
	require.NoError(t, err)

	got, err := enc.Marshal(params)
	require.NoError(t, err)

	require.Equal(
		t,
		"82a263616c672664747970656a7075626c69632d6b6579a263616c6739010064747970656a7075626c69632d6b6579",
		hex.EncodeToString(got),
	)
}

// see https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#example-da70519c
func TestEncodeMakeCredentialRequest(t *testing.T) {
	clientDataHash, err := hex.DecodeString("687134968222ec17202e42505f8ed2b16ae22f16bb05b88c25db9e602645f141")
	require.NoError(t, err)

	userID, err := hex.DecodeString("3082019330820138a0030201023082019330820138a003020102308201933082")
	require.NoError(t, err)

	req := MakeCredentialRequest{
		ClientDataHash: clientDataHash,
		RP: CredentialRpEntity{
			ID:   "example.com",
			Name: "Acme",
		},
		User: CredentialUserEntity{
			ID:          userID,
			Icon:        "https://pics.example.com/00/p/aBjjjpqPb.png",
			Name:        "johnpsmith@example.com",
			DisplayName: "John P. Smith",
		},
		PubKeyCredParams: []CredentialParam{
			PublicKeyES256,
			PublicKeyRS256,
		},
		Options: AuthenticatorOptions{
			ResidentKey: true,
		},
	}

	enc, err := cbor.CTAP2EncOptions().EncMode()
	require.NoError(t, err)

	got, err := enc.Marshal(req)
	require.NoError(t, err)

	require.Equal(
		t,
		"a5015820687134968222ec17202e42505f8ed2b16ae22f16bb05b88c25db9e602645f14102a26269646b6578616d706c652e636f6d646e616d656441636d6503a462696458203082019330820138a0030201023082019330820138a0030201023082019330826469636f6e782b68747470733a2f2f706963732e6578616d706c652e636f6d2f30302f702f61426a6a6a707150622e706e67646e616d65766a6f686e70736d697468406578616d706c652e636f6d6b646973706c61794e616d656d4a6f686e20502e20536d6974680482a263616c672664747970656a7075626c69632d6b6579a263616c6739010064747970656a7075626c69632d6b657907a162726bf5",
		hex.EncodeToString(got),
	)
}
