package ed25519

import (
	"testing"

	ed25519 "filippo.io/edwards25519"
)

func TestKeyGen(t *testing.T) {
	tests := []struct {
		name           string
		wantPublicKey  *ed25519.Point
		wantPrivateKey *ed25519.Scalar
		wantErr        bool
	}{
		{
			name:    "TestKeyGen",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPublicKey, gotPrivateKey, err := KeyGen()
			if (err != nil) != tt.wantErr {
				t.Errorf("KeyGen() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			t.Logf("KeyGen() gotPublicKey = %v, gotPrivateKey = %v", gotPublicKey, gotPrivateKey)
		})
	}
}
