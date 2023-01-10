package sumcheck

import (
	"crypto/rand"
	rand2 "math/rand"
	"testing"
	"time"

	"filippo.io/edwards25519"
	"github.com/auti-project/auti-core/commitment"
	"github.com/auti-project/auti-core/transaction"
)

func checkOrgOneTypeSetUp(numTXs int) (*edwards25519.Point, *edwards25519.Point, []*transaction.Hidden) {
	randBytes := make([]byte, 64)
	_, err := rand.Read(randBytes)
	if err != nil {
		panic(err)
	}
	randScalar, err := edwards25519.NewScalar().SetUniformBytes(randBytes)
	if err != nil {
		panic(err)
	}
	g := edwards25519.NewGeneratorPoint()
	g.ScalarMult(randScalar, g)
	_, err = rand.Read(randBytes)
	if err != nil {
		panic(err)
	}
	randScalar, err = edwards25519.NewScalar().SetUniformBytes(randBytes)
	if err != nil {
		panic(err)
	}
	h := edwards25519.NewGeneratorPoint()
	h.ScalarMult(randScalar, h)
	lastCommit, err := commitment.Commit(12345, time.Now().UnixNano(), 0, g, h)
	if err != nil {
		panic(err)
	}
	lastCommitPoint, err := new(edwards25519.Point).SetBytes(lastCommit)
	if err != nil {
		panic(err)
	}
	currCommitPoint := new(edwards25519.Point).Set(lastCommitPoint)
	txList := dummyTXs(g, h, numTXs)
	tmp := new(edwards25519.Point)
	for _, tx := range txList {
		_, err = tmp.SetBytes(tx.Commitment)
		if err != nil {
			panic(err)
		}
		currCommitPoint.Add(currCommitPoint, tmp)
	}
	return lastCommitPoint, currCommitPoint, txList
}

func dummyTXs(g, h *edwards25519.Point, numTXs int) []*transaction.Hidden {
	randBytes := make([]byte, 64)
	txList := make([]*transaction.Hidden, numTXs)
	for i := 0; i < numTXs; i++ {
		_, err := rand.Read(randBytes)
		if err != nil {
			panic(err)
		}
		sender := string(randBytes)
		_, err = rand.Read(randBytes)
		if err != nil {
			panic(err)
		}
		receiver := string(randBytes)
		amount := rand2.Int63()
		tx := &transaction.Plain{
			Sender:    sender,
			Receiver:  receiver,
			Amount:    amount,
			Timestamp: time.Now().UnixNano(),
		}
		txList[i], err = tx.Hide(uint64(i), g, h)
		if err != nil {
			panic(err)
		}
	}
	return txList
}

func Test_checkOrgOneTypeEpoch(t *testing.T) {
	lastCommit, currCommit, txList := checkOrgOneTypeSetUp(100)
	type args struct {
		lastCommit []byte
		currCommit []byte
		txList     []*transaction.Hidden
	}
	tests := []struct {
		name    string
		args    args
		want    *edwards25519.Point
		wantErr bool
	}{
		{
			name: "Test_checkOrgOneTypeEpoch",
			args: args{
				lastCommit: lastCommit.Bytes(),
				currCommit: currCommit.Bytes(),
				txList:     txList,
			},
			want:    edwards25519.NewIdentityPoint(),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := checkOrgOneTypeEpoch(tt.args.lastCommit, tt.args.currCommit, tt.args.txList)
			if (err != nil) != tt.wantErr {
				t.Errorf("checkOrgOneTypeEpoch() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got.Equal(tt.want) == 0 {
				t.Errorf("checkOrgOneTypeEpoch() got = %v, want %v", got, tt.want)
			}
		})
	}
}
