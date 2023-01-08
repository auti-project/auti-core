package auditing

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// Record is the struct for storing the auditing records
type Record struct {
	Payload string `json:"payload"`
	Type    int    `json:"type"`
	OrgID   string `json:"org_id"`
}

// NewRecord creates a new record
func NewRecord(payload []byte, recordType int, orgID string) *Record {
	return &Record{
		Payload: hex.EncodeToString(payload),
		Type:    recordType,
		OrgID:   orgID,
	}
}

// KeyVal returns the key and value for the record to be stored on-chain
func (r *Record) KeyVal() (string, []byte, error) {
	jsonObj, err := json.Marshal(r)
	if err != nil {
		return "", nil, err
	}
	sha256Hash := sha256.New()
	sha256Hash.Write(jsonObj)
	return hex.EncodeToString(sha256Hash.Sum(nil)), jsonObj, nil
}

// Reveal reveals the data in the payload in bytes
func (r *Record) Reveal() ([]byte, error) {
	return hex.DecodeString(r.Payload)
}
