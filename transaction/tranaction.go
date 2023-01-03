package transaction

import (
	"crypto/sha256"

	ed25519 "filippo.io/edwards25519"
	"github.com/auti-project/auti-core/commitment"
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
func (p *Plain) Hide(counter uint64, publicKey *ed25519.Point) (*Hidden, error) {
	hashFunc := sha256.New()
	hashFunc.Write([]byte(p.Sender))
	senderHash := hashFunc.Sum(nil)
	hashFunc.Reset()
	hashFunc.Write([]byte(p.Receiver))
	receiverHash := hashFunc.Sum(nil)
	c, err := commitment.Commit(p.Amount, p.Timestamp, counter, publicKey)
	if err != nil {
		return nil, err
	}
	return &Hidden{
		Sender:     senderHash,
		Receiver:   receiverHash,
		Commitment: c,
		Auxiliary:  p.Auxiliary,
		Timestamp:  p.Timestamp,
	}, nil
}
