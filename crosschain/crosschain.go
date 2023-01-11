package crosschain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// Record is the cross-chain record on chain
type Record struct {
	Commitment  string `json:"Commit"`
	MerkleProof string `json:"Proof"`
	MerkleRoot  string `json:"Root"`
}

// NewRecord creates a new cross-chain record
func NewRecord(commitment, proof, root []byte) (*Record, error) {
	proofBytes, err := json.Marshal(proof)
	if err != nil {
		return nil, err
	}
	return &Record{
		Commitment:  hex.EncodeToString(commitment),
		MerkleProof: hex.EncodeToString(proofBytes),
		MerkleRoot:  hex.EncodeToString(root),
	}, nil
}

// KeyVal generates the key-value pair of the record to be stored on-chain
func (r *Record) KeyVal() (string, []byte, error) {
	jsonBytes, err := json.Marshal(r)
	if err != nil {
		return "", nil, err
	}
	sha256Hash := sha256.New()
	sha256Hash.Write(jsonBytes)
	return hex.EncodeToString(sha256Hash.Sum(nil)), jsonBytes, nil
}

// Reveal reveals the data recorded
func (r *Record) Reveal() (commit, proof, root []byte, err error) {
	commit, err = hex.DecodeString(r.Commitment)
	if err != nil {
		return
	}
	proof, err = hex.DecodeString(r.MerkleProof)
	if err != nil {
		return
	}
	root, err = hex.DecodeString(r.MerkleRoot)
	return
}
