package transaction

import (
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	ed25519 "filippo.io/edwards25519"
)

func TestPlain_HidePair(t *testing.T) {
	g, h := paramSetup()
	type fields struct {
		Sender    string
		Receiver  string
		Amount    int64
		Auxiliary []byte
		Timestamp int64
	}
	type args struct {
		counter uint64
		g       *ed25519.Point
		h       *ed25519.Point
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantH1  *Hidden
		wantH2  *Hidden
		wantErr bool
	}{
		{
			name: "Test_HidePair",
			fields: fields{
				Sender:    "sender",
				Receiver:  "receiver",
				Amount:    100,
				Timestamp: time.Now().UnixNano(),
			},
			args: args{
				counter: 100,
				g:       g,
				h:       h,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Plain{
				Sender:    tt.fields.Sender,
				Receiver:  tt.fields.Receiver,
				Amount:    tt.fields.Amount,
				Auxiliary: tt.fields.Auxiliary,
				Timestamp: tt.fields.Timestamp,
			}
			got1, got2, err := p.HidePair(tt.args.counter, tt.args.g, tt.args.h)
			if (err != nil) != tt.wantErr {
				t.Errorf("HidePair() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			point1, err := new(ed25519.Point).SetBytes(got1.Commitment)
			if err != nil {
				t.Errorf("cannot convert to EC point, error = %v", err)
			}
			point2, err := new(ed25519.Point).SetBytes(got2.Commitment)
			if err != nil {
				t.Errorf("cannot convert to EC point, error = %v", err)
			}
			point1.Add(point1, point2)
			if point1.Equal(ed25519.NewIdentityPoint()) == 0 {
				fmt.Println(point1)
				fmt.Println(point2)
				t.Errorf("HidePair() commitment not equal to zero")
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
	g = ed25519.NewGeneratorPoint()
	g.ScalarMult(randScalar, g)
	_, err = rand.Read(randBytes)
	handleErr(err)
	_, err = randScalar.SetUniformBytes(randBytes)
	handleErr(err)
	h = ed25519.NewGeneratorPoint()
	h.ScalarMult(randScalar, h)
	return
}
func handleErr(err error) {
	if err != nil {
		panic(err)
	}
}
