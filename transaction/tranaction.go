package transaction

import (
	"crypto/sha256"
	"encoding/binary"
	"math/big"
)

// Plain is the struct for plaintext transaction
type Plain struct {
	Sender    string `json:"sender"`
	Receiver  string `json:"receiver"`
	Amount    int64  `json:"amount"`
	Auxiliary []byte `json:"aux"`
	Timestamp int64  `json:"timestamp"`
}

// Hidden is the struct for hidden transaction
type Hidden struct {
	Sender     []byte `json:"sender"`
	Receiver   []byte `json:"receiver"`
	Commitment []byte `json:"commit"`
	Auxiliary  []byte `json:"aux"`
	Timestamp  int64  `json:"timestamp"`
}

// Hide converts a plaintext transaction to a hidden transaction
func (p *Plain) Hide(counter uint64, g, n *big.Int) *Hidden {
	commitment := new(big.Int).Exp(g, big.NewInt(p.Amount), n)
	hashFunc := sha256.New()
	hashFunc.Write([]byte(p.Sender))
	senderHash := hashFunc.Sum(nil)
	hashFunc.Reset()
	hashFunc.Write([]byte(p.Receiver))
	receiverHash := hashFunc.Sum(nil)
	hashFunc.Reset()
	timestampBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(timestampBytes, uint64(p.Timestamp))
	counterBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(counterBytes, counter)
	hashFunc.Write(timestampBytes)
	hashFunc.Write(counterBytes)
	tcHash := hashFunc.Sum(nil)
	tcHashBigInt := new(big.Int).SetBytes(tcHash)
	commitment.Mul(commitment, tcHashBigInt)
	commitment.Mod(commitment, n)
	return &Hidden{
		Sender:     senderHash,
		Receiver:   receiverHash,
		Commitment: commitment.Bytes(),
		Auxiliary:  p.Auxiliary,
		Timestamp:  p.Timestamp,
	}
}
