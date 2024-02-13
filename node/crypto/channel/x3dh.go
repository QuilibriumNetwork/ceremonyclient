package channel

import (
	"crypto/sha512"

	"golang.org/x/crypto/hkdf"
	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/core/curves"
)

var domainSeparators = map[string][]byte{
	curves.ED448().Name: {
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF,
	},
}

func SenderX3DH(
	sendingIdentityPrivateKey curves.Scalar,
	sendingEphemeralPrivateKey curves.Scalar,
	receivingIdentityKey curves.Point,
	receivingSignedPreKey curves.Point,
	sessionKeyLength uint8,
) []byte {
	xdh1 := receivingSignedPreKey.Mul(
		sendingIdentityPrivateKey,
	).ToAffineCompressed()
	xdh2 := receivingIdentityKey.Mul(
		sendingEphemeralPrivateKey,
	).ToAffineCompressed()
	xdh3 := receivingSignedPreKey.Mul(
		sendingEphemeralPrivateKey,
	).ToAffineCompressed()
	salt := make([]byte, sessionKeyLength)
	x3dh := hkdf.New(sha512.New, append(
		append(
			append(
				append([]byte{}, domainSeparators[receivingIdentityKey.CurveName()]...),
				xdh1[:]...),
			xdh2[:]...),
		xdh3[:]...), salt, []byte("quilibrium-x3dh"))
	sessionKey := make([]byte, sessionKeyLength)
	if _, err := x3dh.Read(sessionKey[:]); err != nil {
		return nil
	}

	return sessionKey
}

func ReceiverX3DH(
	sendingIdentityPrivateKey curves.Scalar,
	sendingSignedPrePrivateKey curves.Scalar,
	receivingIdentityKey curves.Point,
	receivingEphemeralKey curves.Point,
	sessionKeyLength uint8,
) []byte {
	xdh1 := receivingIdentityKey.Mul(
		sendingSignedPrePrivateKey,
	).ToAffineCompressed()
	xdh2 := receivingEphemeralKey.Mul(
		sendingIdentityPrivateKey,
	).ToAffineCompressed()
	xdh3 := receivingEphemeralKey.Mul(
		sendingSignedPrePrivateKey,
	).ToAffineCompressed()
	salt := make([]byte, sessionKeyLength)
	x3dh := hkdf.New(sha512.New, append(
		append(
			append(
				append([]byte{}, domainSeparators[receivingIdentityKey.CurveName()]...),
				xdh1[:]...),
			xdh2[:]...),
		xdh3[:]...), salt, []byte("quilibrium-x3dh"))
	sessionKey := make([]byte, sessionKeyLength)
	if _, err := x3dh.Read(sessionKey[:]); err != nil {
		return nil
	}

	return sessionKey
}
