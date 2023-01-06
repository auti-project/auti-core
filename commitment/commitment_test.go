package commitment

import (
	"reflect"
	"testing"

	ed25519 "filippo.io/edwards25519"
)

func TestCommit(t *testing.T) {
	wantBytes := make([]byte, 32)
	wantBytes[0] = 1
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Commit(tt.args.amount, tt.args.timestamp, tt.args.counter, tt.args.g, tt.args.h)
			if (err != nil) != tt.wantErr {
				t.Errorf("Commit() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Commit() got = %v, want %v", got, tt.want)
			}
		})
	}
}
