package tree

import (
	"bytes"
	"testing"

	ed25519 "filippo.io/edwards25519"
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
	g, _ := transaction.DummyGetKeyPairs()
	h, _ := transaction.DummyGetKeyPairs()
	txList, err := transaction.DummyTXs(size)
	if err != nil {
		panic(err)
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
	point, err := new(ed25519.Point).SetBytes(txList[0].Commitment)
	if err != nil {
		panic(err)
	}
	for i := 1; i < len(txList); i++ {
		newPoint, err := new(ed25519.Point).SetBytes(txList[i].Commitment)
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
			wantErr: false,
		},
		{
			name: "TestNew_1000",
			args: args{
				txList: getDummyHiddenTxList(1000),
			},
			wantErr: false,
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
