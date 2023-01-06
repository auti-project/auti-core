package transaction

import (
	crand "crypto/rand"
	"math/rand"
	"sync"
	"time"

	"filippo.io/edwards25519"
	"github.com/auti-project/auti-core/ed25519"
)

var (
	publicKey  *edwards25519.Point
	privateKey *edwards25519.Scalar
	onceKeyGen sync.Once
)

// DummyGetKeyPairs returns the public/private key pairs of ED25519 curve
func DummyGetKeyPairs() (*edwards25519.Point, *edwards25519.Scalar) {
	onceKeyGen.Do(func() {
		var err error
		publicKey, privateKey, err = ed25519.KeyGen()
		if err != nil {
			panic(err)
		}
	})
	return publicKey, privateKey
}

// DummyTX generates a dummy plaintext transaction
func DummyTX() (*Plain, error) {
	randBuff := make([]byte, 10)
	_, err := crand.Read(randBuff)
	if err != nil {
		return nil, err
	}
	sender := string(randBuff)
	_, err = crand.Read(randBuff)
	if err != nil {
		return nil, err
	}
	receiver := string(randBuff)
	amount := rand.Int63()
	timestamp := time.Now().UnixNano()
	return &Plain{
		Sender:    sender,
		Receiver:  receiver,
		Amount:    amount,
		Timestamp: timestamp,
	}, nil
}

// DummyTXs generates a list of dummy plaintext transactions
func DummyTXs(num int) ([]*Plain, error) {
	txList := make([]*Plain, num)
	for i := range txList {
		tx, err := DummyTX()
		if err != nil {
			return nil, err
		}
		txList[i] = tx
	}
	return txList, nil
}
