package transaction

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"

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

// NewPlain creates a new plaintext transaction
func NewPlain(sender, receiver string, amount int64) *Plain {
	return &Plain{
		Sender:   sender,
		Receiver: receiver,
		Amount:   amount,
	}
}

// Hide converts a plaintext transaction to a hidden transaction
func (p *Plain) Hide(counter uint64, g, h *ed25519.Point, negateHash bool) (*Hidden, error) {
	hashFunc := sha256.New()
	hashFunc.Write([]byte(p.Sender))
	senderHash := hashFunc.Sum(nil)
	hashFunc.Reset()
	hashFunc.Write([]byte(p.Receiver))
	receiverHash := hashFunc.Sum(nil)
	c, err := commitment.Commit(p.Amount, p.Timestamp, counter, g, h, negateHash)
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

// HidePair creates the hidden transaction pairs
func (p *Plain) HidePair(counter uint64, g, h *ed25519.Point) (h1, h2 *Hidden, err error) {
	hashFunc := sha256.New()
	hashFunc.Write([]byte(p.Sender))
	senderHash := hashFunc.Sum(nil)
	hashFunc.Reset()
	hashFunc.Write([]byte(p.Receiver))
	receiverHash := hashFunc.Sum(nil)
	var c1, c2 []byte
	if c1, err = commitment.Commit(p.Amount, p.Timestamp, counter, g, h, false); err != nil {
		return
	}
	if c2, err = commitment.Commit(-p.Amount, p.Timestamp, counter, g, h, true); err != nil {
		return
	}
	h1 = &Hidden{
		Sender:     senderHash,
		Receiver:   receiverHash,
		Commitment: c1,
		Auxiliary:  p.Auxiliary,
		Timestamp:  p.Timestamp,
	}
	h2 = &Hidden{
		Sender:     receiverHash,
		Receiver:   senderHash,
		Commitment: c2,
		Auxiliary:  p.Auxiliary,
		Timestamp:  p.Timestamp,
	}
	return
}

// Hidden is the struct for hidden transaction
type Hidden struct {
	Sender     []byte
	Receiver   []byte
	Commitment []byte
	Auxiliary  []byte
	Timestamp  int64
}

// NewHidden creates a new hidden transaction
func NewHidden(sender, receiver, commitment, auxiliary []byte, timestamp int64) *Hidden {
	return &Hidden{
		Sender:     sender,
		Receiver:   receiver,
		Commitment: commitment,
		Auxiliary:  auxiliary,
		Timestamp:  timestamp,
	}
}

// ToOnChain converts a hidden transaction to an on-chain transaction
func (h *Hidden) ToOnChain() *OnChain {
	// convert int64 timestamp to string
	timestampStr := strconv.FormatInt(h.Timestamp, 10)
	return &OnChain{
		Sender:     hex.EncodeToString(h.Sender),
		Receiver:   hex.EncodeToString(h.Receiver),
		Commitment: hex.EncodeToString(h.Commitment),
		Auxiliary:  hex.EncodeToString(h.Auxiliary),
		Timestamp:  timestampStr,
	}
}

// Serialize returns the hidden transaction's commitment, for Merkle Tree generation purpose
func (h *Hidden) Serialize() ([]byte, error) {
	return h.Commitment, nil
}

// OnChain is the struct for on-chain transaction
type OnChain struct {
	Sender     string `json:"Sender"`
	Receiver   string `json:"Receiver"`
	Commitment string `json:"Commit"`
	Auxiliary  string `json:"Aux"`
	Timestamp  string `json:"Timestamp"`
}

// NewOnChain creates a new on-chain transaction
func NewOnChain(sender, receiver, commitment, auxiliary, timestamp string) *OnChain {
	return &OnChain{
		Sender:     sender,
		Receiver:   receiver,
		Commitment: commitment,
		Auxiliary:  auxiliary,
		Timestamp:  timestamp,
	}
}

// ToHide converts an on-chain transaction to a hidden transaction
func (o *OnChain) ToHide() (*Hidden, error) {
	// convert string timestamp to int64
	timestampInt, err := strconv.ParseInt(o.Timestamp, 10, 64)
	if err != nil {
		return nil, err
	}
	hiddenTX := new(Hidden)
	hiddenTX.Sender, err = hex.DecodeString(o.Sender)
	if err != nil {
		return nil, err
	}
	hiddenTX.Receiver, err = hex.DecodeString(o.Receiver)
	if err != nil {
		return nil, err
	}
	hiddenTX.Commitment, err = hex.DecodeString(o.Commitment)
	if err != nil {
		return nil, err
	}
	hiddenTX.Auxiliary, err = hex.DecodeString(o.Auxiliary)
	if err != nil {
		return nil, err
	}
	hiddenTX.Timestamp = timestampInt
	return hiddenTX, nil
}

// KeyVal composes the key value pair for the transaction to be stored on-chain
func (o *OnChain) KeyVal() (string, []byte, error) {
	txJSON, err := json.Marshal(o)
	if err != nil {
		return "", nil, err
	}
	sha256Hash := sha256.New()
	sha256Hash.Write(txJSON)
	return hex.EncodeToString(sha256Hash.Sum(nil)), txJSON, nil
}
