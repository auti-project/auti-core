package commitment

import (
	"crypto/rand"
	"reflect"
	"testing"

	ed25519 "filippo.io/edwards25519"
)

func TestCommit(t *testing.T) {
	wantBytes := make([]byte, 32)
	wantBytes[0] = 1
	g, h := paramSetup()
	type args struct {
		amount    int64
		timestamp int64
		counter   uint64
		g         *ed25519.Point
		h         *ed25519.Point
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "Test_Commitment",
			args: args{
				amount:    100,
				timestamp: 100,
				counter:   100,
				g:         ed25519.NewIdentityPoint(),
				h:         ed25519.NewIdentityPoint(),
			},
			want:    wantBytes,
			wantErr: false,
		},
		{
			name: "Test_Commitment_Negative",
			args: args{
				amount:    100,
				timestamp: 100,
				counter:   100,
				g:         g,
				h:         h,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Commit(tt.args.amount, tt.args.timestamp, tt.args.counter, tt.args.g, tt.args.h, false)
			if (err != nil) != tt.wantErr {
				t.Errorf("Commit() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.want != nil && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Commit() got = %v, want %v", got, tt.want)
			}
			pair, err := Commit(-tt.args.amount, tt.args.timestamp, tt.args.counter, tt.args.g, tt.args.h, true)
			if err != nil {
				t.Errorf("pair Commit() error = %v, wantErr %v", err, tt.wantErr)
			}
			point, err := new(ed25519.Point).SetBytes(got)
			if err != nil {
				t.Errorf("cannot convert to point = %v", err)
			}
			pairPoint, err := new(ed25519.Point).SetBytes(pair)
			if err != nil {
				t.Errorf("cannot convert to point = %v", err)
			}
			point.Add(point, pairPoint)
			if point.Equal(ed25519.NewIdentityPoint()) == 0 {
				t.Errorf("Commit() implementation error")
			}
		})
	}
}

func paramSetup() (g, h *ed25519.Point) {
	randBytes := make([]byte, 64)
	_, err := rand.Read(randBytes)
	handleErr(err)
	randScalar := ed25519.NewScalar()
	_, err = randScalar.SetUniformBytes(randBytes)
	handleErr(err)
	g = ed25519.NewIdentityPoint()
	g.ScalarMult(randScalar, g)
	_, err = rand.Read(randBytes)
	handleErr(err)
	_, err = randScalar.SetUniformBytes(randBytes)
	handleErr(err)
	h = ed25519.NewIdentityPoint()
	h.ScalarMult(randScalar, h)
	return
}

func handleErr(err error) {
	if err != nil {
		panic(err)
	}
}
