package tree

import (
	"bytes"
	"math/rand"
	"testing"
	"time"

	"filippo.io/edwards25519"
	"github.com/auti-project/auti-core/ed25519"
	"github.com/auti-project/auti-core/transaction"
)

func Test_calHeight(t *testing.T) {
	type args struct {
		txLen int
	}
	tests := []struct {
		name string
		args args
		want int
	}{
		{
			name: "Test_calHeight_5",
			args: args{
				txLen: 5,
			},
			want: 4,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := calHeight(tt.args.txLen); got != tt.want {
				t.Errorf("calHeight() = %v, want %v", got, tt.want)
			}
		})
	}
}

func getDummyHiddenTxList(size int) []*transaction.Hidden {
	// g, _ := transaction.DummyGetKeyPairs()
	// h, _ := transaction.DummyGetKeyPairs()
	g, _, err := ed25519.KeyGen()
	if err != nil {
		panic(err)
	}
	h, _, err := ed25519.KeyGen()
	if err != nil {
		panic(err)
	}
	txList := make([]*transaction.Plain, size)
	randBytes := make([]byte, 32)
	for i := 0; i < size; i++ {
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
		amount := rand.Int63()
		txList[i] = &transaction.Plain{
			Sender:    sender,
			Receiver:  receiver,
			Amount:    amount,
			Timestamp: time.Now().Unix(),
		}
	}
	hiddenTxList := make([]*transaction.Hidden, size)
	for i := 0; i < size; i++ {
		hiddenTxList[i], err = txList[i].Hide(uint64(i), g, h)
		if err != nil {
			panic(err)
		}
	}
	return hiddenTxList
}

func commitmentSum(txList []*transaction.Hidden) []byte {
	point, err := new(edwards25519.Point).SetBytes(txList[0].Commitment)
	if err != nil {
		panic(err)
	}
	for i := 1; i < len(txList); i++ {
		newPoint, err := new(edwards25519.Point).SetBytes(txList[i].Commitment)
		if err != nil {
			panic(err)
		}
		point.Add(point, newPoint)
	}
	return point.Bytes()
}

func TestNew(t *testing.T) {
	type args struct {
		txList []*transaction.Hidden
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "TestNew_1",
			args: args{
				txList: getDummyHiddenTxList(1),
			},
		},
		{
			name: "TestNew_2",
			args: args{
				txList: getDummyHiddenTxList(2),
			},
		},
		{
			name: "TestNew_3",
			args: args{
				txList: getDummyHiddenTxList(3),
			},
		},
		{
			name: "TestNew_4",
			args: args{
				txList: getDummyHiddenTxList(4),
			},
		},
		{
			name: "TestNew_8",
			args: args{
				txList: getDummyHiddenTxList(8),
			},
		},
		{
			name: "TestNew_1000",
			args: args{
				txList: getDummyHiddenTxList(1000),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := New(tt.args.txList)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !bytes.Equal(got.Root, commitmentSum(tt.args.txList)) {
				t.Errorf("New() got.Root = %v, want %v", got.Root, commitmentSum(tt.args.txList))
			}
		})
	}
}

func BenchmarkNew(b *testing.B) {
	txList := getDummyHiddenTxList(1000)
	for i := 0; i < b.N; i++ {
		if _, err := New(txList); err != nil {
			b.Errorf("New() error = %v", err)
		}
	}
}
