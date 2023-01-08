package auditing

import (
	"crypto/rand"
	"encoding/hex"

	ed25519 "filippo.io/edwards25519"
)

// DummyRecord creates a dummy record
func DummyRecord(orgID string) (*Record, error) {
	point := ed25519.NewGeneratorPoint()
	randBytes := make([]byte, 64)
	_, err := rand.Read(randBytes)
	if err != nil {
		return nil, err
	}
	var scalar *ed25519.Scalar
	scalar, err = ed25519.NewScalar().SetUniformBytes(randBytes)
	if err != nil {
		return nil, err
	}
	point.ScalarMult(scalar, point)
	return &Record{
		Payload: hex.EncodeToString(point.Bytes()),
		Type:    0,
		OrgID:   orgID,
	}, nil
}

// DummyRecords creates a slice of dummy records
func DummyRecords(orgID string, count int) ([]*Record, error) {
	records := make([]*Record, count)
	for i := 0; i < count; i++ {
		record, err := DummyRecord(orgID)
		if err != nil {
			return nil, err
		}
		records[i] = record
	}
	return records, nil
}
