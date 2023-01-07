package digest

import (
	"crypto/rand"
	"encoding/hex"

	ed25519 "filippo.io/edwards25519"
)

// DummyDigest generates a dummy digest for a given organization ID
func DummyDigest(orgID string) (*Digest, error) {
	point := ed25519.NewIdentityPoint()
	randBytes := make([]byte, 64)
	_, err := rand.Read(randBytes)
	if err != nil {
		return nil, err
	}
	var scalar *ed25519.Scalar
	scalar, err = ed25519.NewScalar().SetUniformBytes(randBytes)
	if err != nil {
		return nil, err
	}
	point.ScalarMult(scalar, point)
	return &Digest{
		Data:  hex.EncodeToString(point.Bytes()),
		OrgID: orgID,
	}, nil
}
