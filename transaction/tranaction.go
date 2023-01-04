package transaction

import (
	"crypto/sha256"
	"encoding/json"

	ed25519 "filippo.io/edwards25519"
	"github.com/auti-project/auti-core/commitment"
)

// Plain is the struct for plaintext transaction
type Plain struct {
	Sender    string
	Receiver  string
	Amount    int64
	Auxiliary []byte
	Timestamp int64
}

// Hidden is the struct for hidden transaction
type Hidden struct {
	Sender     []byte
	Receiver   []byte
	Commitment []byte
	Auxiliary  []byte
	Timestamp  int64
}

// OnChain is the struct for on-chain transaction
type OnChain struct {
	Sender     string `json:"Sender"`
	Receiver   string `json:"Receiver"`
	Commitment string `json:"Commit"`
	Auxiliary  string `json:"Aux"`
	Timestamp  int64  `json:"Timestamp"`
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

// OnChain converts a hidden transaction to an on-chain transaction
func (h *Hidden) OnChain() *OnChain {
	return &OnChain{
		Sender:     string(h.Sender),
		Receiver:   string(h.Receiver),
		Commitment: string(h.Commitment),
		Auxiliary:  string(h.Auxiliary),
		Timestamp:  h.Timestamp,
	}
}

// Hide converts an on-chain transaction to a hidden transaction
func (o *OnChain) Hide() *Hidden {
	return &Hidden{
		Sender:     []byte(o.Sender),
		Receiver:   []byte(o.Receiver),
		Commitment: []byte(o.Commitment),
		Auxiliary:  []byte(o.Auxiliary),
		Timestamp:  o.Timestamp,
	}
}

// KeyVal composes the key value pair for the transaction to be stored on-chain
func (o *OnChain) KeyVal() (string, []byte, error) {
	sha256Hash := sha256.New()
	txJSON, err := json.Marshal(o)
	if err != nil {
		return "", nil, err
	}
	sha256Hash.Write(txJSON)
	return string(sha256Hash.Sum(nil)), txJSON, nil
}
