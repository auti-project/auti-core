package commitment

import (
	"crypto/sha256"
	"encoding/binary"

	ed25519 "filippo.io/edwards25519"
)

// Commit generates a commitment from amount, timestamp, counter and the public key (ED25519 point)
// Commitment = r * G * amount_scalar * Hash(timestamp || counter)
func Commit(amount, timestamp int64, counter uint64, g, h *ed25519.Point, negateHash bool) ([]byte, error) {
	var isAmountNegative bool
	if amount < 0 {
		isAmountNegative = true
		amount = -amount
	}
	amountBytes := make([]byte, 64)
	binary.BigEndian.PutUint64(amountBytes, uint64(amount))
	amountScalar := ed25519.NewScalar()
	_, err := amountScalar.SetUniformBytes(amountBytes)
	if err != nil {
		return nil, err
	}
	if isAmountNegative {
		amountScalar.Negate(amountScalar)
	}
	timestampBytes := make([]byte, 64)
	binary.BigEndian.PutUint64(timestampBytes, uint64(timestamp))
	counterBytes := make([]byte, 64)
	binary.BigEndian.PutUint64(counterBytes, counter)
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
	commitment := new(ed25519.Point).Set(g)
	commitment.ScalarMult(amountScalar, commitment)
	tmp := new(ed25519.Point).Set(h)
	tmp.ScalarMult(hashScalar, tmp)
	if negateHash {
		commitment.Subtract(commitment, tmp)
	} else {
		commitment.Add(commitment, tmp)
	}
	return commitment.Bytes(), nil
}
