package ed25519

import (
	"crypto/rand"

	ed25519 "filippo.io/edwards25519"
)

// KeyGen generates a new public/private key pair based on the Ed25519 curve
func KeyGen() (publicKey *ed25519.Point, privateKey *ed25519.Scalar, err error) {
	randBytes := make([]byte, 64)
	_, err = rand.Read(randBytes)
	if err != nil {
		return
	}
	privateKey = ed25519.NewScalar()
	_, err = privateKey.SetUniformBytes(randBytes)
	if err != nil {
		return
	}
	publicKey = ed25519.NewGeneratorPoint().ScalarBaseMult(privateKey)
	return
}
