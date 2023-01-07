package digest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// Digest is the struct for digest of a batch of transactions
type Digest struct {
	Data  string `json:"data"`
	OrgID string `json:"org_id"`
}

// NewDigest creates a new digest for the input data and organization ID
func NewDigest(data []byte, orgID string) *Digest {
	return &Digest{
		Data:  hex.EncodeToString(data),
		OrgID: orgID,
	}
}

// KeyVal returns the key-value pair of the digest to be recorded on-chain
func (d *Digest) KeyVal() (string, []byte, error) {
	digestJSON, err := json.Marshal(d)
	if err != nil {
		return "", nil, err
	}
	sha256Hash := sha256.New()
	sha256Hash.Write(digestJSON)
	return hex.EncodeToString(sha256Hash.Sum(nil)), digestJSON, nil
}

// Reveal reveals the byte data of a digest
func (d *Digest) Reveal() ([]byte, error) {
	return hex.DecodeString(d.Data)
}
