package sumcheck

import (
	"crypto/rand"
	"fmt"

	"filippo.io/edwards25519"
	"github.com/auti-project/auti-core/transaction"
)

func CheckOrgEpoch(lastCommits, currCommits [][]byte, txLists [][]*transaction.Hidden) (
	[]*edwards25519.Point, bool, error,
) {
	numLastCommits, numCurrCommits, numTXLists := len(lastCommits), len(currCommits), len(txLists)
	if numLastCommits != numCurrCommits || numLastCommits != numTXLists {
		return nil, false,
			fmt.Errorf(
				"number of last commits, current commits and transaction lists are not equal: %d, %d, %d",
				numLastCommits, numCurrCommits, numTXLists)
	}

	if numLastCommits == 0 {
		return nil, false, fmt.Errorf("number of last commits, current commits and transaction lists are zero")
	}

	commits := make([]*edwards25519.Point, numLastCommits)
	for i := 0; i < numLastCommits; i++ {
		commit, err := computeTXCommitCheck(lastCommits[i], currCommits[i], txLists[i])
		if err != nil {
			return nil, false, err
		}
		commits[i] = commit
	}
	check := edwards25519.NewIdentityPoint()
	for _, commit := range commits {
		check.Add(check, commit)
	}
	return commits, check.Equal(edwards25519.NewIdentityPoint()) == 1, nil
}

func computeTXCommitCheck(lastCommit, currCommit []byte,
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

func CheckAllOrgEpoch(orgLastCommits, orgEpochCommits, orgCurrCommits [][][]byte) (bool, error) {
	var (
		numOrgLastCommits  = len(orgLastCommits)
		numOrgEpochCommits = len(orgEpochCommits)
		numOrgCurrCommits  = len(orgCurrCommits)
	)
	if numOrgLastCommits != numOrgCurrCommits || numOrgLastCommits != numOrgEpochCommits {
		return false,
			fmt.Errorf(
				"number of organizations is not consistent: %d, %d, %d",
				numOrgLastCommits, numOrgCurrCommits, numOrgEpochCommits)
	}

	if numOrgLastCommits == 0 {
		return false, fmt.Errorf("number of organizations is zero")
	}

	overallCheck := edwards25519.NewIdentityPoint()
	for i := 0; i < len(orgLastCommits); i++ {
		check, err := computeOrgCommitCheck(orgLastCommits[i], orgEpochCommits[i], orgCurrCommits[i])
		if err != nil {
			return false, err
		}
		overallCheck.Add(overallCheck, check)
	}
	return overallCheck.Equal(edwards25519.NewIdentityPoint()) == 1, nil
}

func computeOrgCommitCheck(lastCommits, epochCommits, currCommits [][]byte) (*edwards25519.Point, error) {
	numLasts, numCurrents, numEpochs := len(lastCommits), len(currCommits), len(epochCommits)
	if numLasts != numCurrents || numLasts != numEpochs {
		return nil,
			fmt.Errorf(
				"number of last commits, current commits and epoch commits are not equal: %d, %d, %d",
				numLasts, numCurrents, numEpochs)
	}
	if numLasts == 0 {
		return nil, fmt.Errorf("number of last commits, current commits and epoch commits are zero")
	}

	var (
		randBytes  = make([]byte, 64)
		randScalar = new(edwards25519.Scalar)
		orgCheck   = edwards25519.NewIdentityPoint()
	)
	for i := 0; i < numLasts; i++ {
		check, err := new(edwards25519.Point).SetBytes(lastCommits[i])
		if err != nil {
			return nil, err
		}
		epochCommitPoint, err := new(edwards25519.Point).SetBytes(epochCommits[i])
		if err != nil {
			return nil, err
		}
		check.Add(check, epochCommitPoint)
		currCommitPoint, err := new(edwards25519.Point).SetBytes(currCommits[i])
		if err != nil {
			return nil, err
		}
		check.Subtract(check, currCommitPoint)
		_, err = rand.Read(randBytes)
		if err != nil {
			return nil, err
		}
		_, err = randScalar.SetUniformBytes(randBytes)
		if err != nil {
			return nil, err
		}
		check.ScalarMult(randScalar, check)
		orgCheck.Add(orgCheck, check)
	}
	return orgCheck, nil
}
