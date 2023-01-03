package commitment

import (
	"crypto/sha256"
	"encoding/binary"

	ed25519 "filippo.io/edwards25519"
)

// Commit generates a commitment from amount, timestamp, counter and the public key (ED25519 point)
// Commitment = r * G * amount_scalar * Hash(timestamp || counter)
func Commit(amount, timestamp int64, counter uint64, publicKey *ed25519.Point) ([]byte, error) {
	amountBytes := make([]byte, 64)
	binary.BigEndian.PutUint64(amountBytes, uint64(amount))
	amountScalar := ed25519.NewScalar()
	_, err := amountScalar.SetUniformBytes(amountBytes)
	if err != nil {
		return nil, err
	}
	timestampBytes := make([]byte, 64)
	binary.BigEndian.PutUint64(timestampBytes, uint64(timestamp))
	counterBytes := make([]byte, 64)
	binary.BigEndian.PutUint64(counterBytes, uint64(counter))
	hashFunc := sha256.New()
	hashFunc.Write(timestampBytes)
	hashFunc.Write(counterBytes)
	hashVal := hashFunc.Sum(nil)
	hashBytes := make([]byte, 64)
	copy(hashBytes, hashVal)
	hashScalar := ed25519.NewScalar()
	_, err = hashScalar.SetUniformBytes(hashBytes)
	if err != nil {
		return nil, err
	}
	commitment := ed25519.NewIdentityPoint().Set(publicKey)
	commitment.ScalarMult(hashScalar, commitment)
	commitment.ScalarMult(amountScalar, commitment)
	return commitment.Bytes(), nil
}
