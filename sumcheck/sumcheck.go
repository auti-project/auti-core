package sumcheck

import (
	"crypto/rand"
	"fmt"

	"filippo.io/edwards25519"
	"github.com/auti-project/auti-core/transaction"
)

func CheckOrgEpoch(lastCommits [][]byte, currCommits [][]byte, txLists [][]*transaction.Hidden) (bool, error) {
	numLastCommits, numCurrCommits, numTXLists := len(lastCommits), len(currCommits), len(txLists)
	if numLastCommits != numCurrCommits || numLastCommits != numTXLists {
		return false, fmt.Errorf("number of last commits, current commits and transaction lists are not equal: %d, %d, %d",
			numLastCommits, numCurrCommits, numTXLists)
	}
	if numLastCommits == 0 {
		return false, fmt.Errorf("number of last commits, current commits and transaction lists are zero")
	}
	commits := make([]*edwards25519.Point, numLastCommits)
	for i := 0; i < numLastCommits; i++ {
		commit, err := checkOrgOneTypeEpoch(lastCommits[i], currCommits[i], txLists[i])
		if err != nil {
			return false, err
		}
		commits[i] = commit
	}
	b := new(edwards25519.Point).Set(commits[0])
	for i := 1; i < numLastCommits; i++ {
		b.Add(b, commits[i])
	}
	return b.Equal(edwards25519.NewIdentityPoint()) == 1, nil
}

func checkOrgOneTypeEpoch(lastCommit, currCommit []byte,
	txList []*transaction.Hidden) (*edwards25519.Point, error) {
	commit, err := new(edwards25519.Point).SetBytes(lastCommit)
	if err != nil {
		return nil, err
	}
	txCommitPoint := new(edwards25519.Point)
	for _, tx := range txList {
		txCommitPoint, err = new(edwards25519.Point).SetBytes(tx.Commitment)
		if err != nil {
			return nil, err
		}
		commit.Add(commit, txCommitPoint)
	}
	currCommitPoint := new(edwards25519.Point)
	currCommitPoint, err = new(edwards25519.Point).SetBytes(currCommit)
	if err != nil {
		return nil, err
	}
	commit.Subtract(commit, currCommitPoint)
	randBytes := make([]byte, 64)
	_, err = rand.Read(randBytes)
	if err != nil {
		return nil, err
	}
	randScalar := new(edwards25519.Scalar)
	_, err = randScalar.SetUniformBytes(randBytes)
	if err != nil {
		return nil, err
	}
	commit.ScalarMult(randScalar, commit)
	return commit, nil
}
