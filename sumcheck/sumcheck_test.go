package sumcheck

import (
	"crypto/rand"
	rand2 "math/rand"
	"reflect"
	"testing"
	"time"

	"filippo.io/edwards25519"
	"github.com/auti-project/auti-core/commitment"
	"github.com/auti-project/auti-core/transaction"
)

func computeTXCommitCheckSetUp(numTXs int) (*edwards25519.Point, *edwards25519.Point, []*transaction.Hidden) {
	g, h := paramSetup()
	lastCommit, err := commitment.Commit(12345, time.Now().UnixNano(), 0, g, h)
	if err != nil {
		panic(err)
	}
	lastCommitPoint, err := new(edwards25519.Point).SetBytes(lastCommit)
	if err != nil {
		panic(err)
	}
	currCommitPoint := new(edwards25519.Point).Set(lastCommitPoint)
	txList := dummyTXs(g, h, numTXs)
	tmp := new(edwards25519.Point)
	for _, tx := range txList {
		_, err = tmp.SetBytes(tx.Commitment)
		if err != nil {
			panic(err)
		}
		currCommitPoint.Add(currCommitPoint, tmp)
	}
	return lastCommitPoint, currCommitPoint, txList
}

func paramSetup() (*edwards25519.Point, *edwards25519.Point) {
	randBytes := make([]byte, 64)
	_, err := rand.Read(randBytes)
	if err != nil {
		panic(err)
	}
	randScalar, err := edwards25519.NewScalar().SetUniformBytes(randBytes)
	if err != nil {
		panic(err)
	}
	g := edwards25519.NewGeneratorPoint()
	g.ScalarMult(randScalar, g)
	_, err = rand.Read(randBytes)
	if err != nil {
		panic(err)
	}
	randScalar, err = edwards25519.NewScalar().SetUniformBytes(randBytes)
	if err != nil {
		panic(err)
	}
	h := edwards25519.NewGeneratorPoint()
	h.ScalarMult(randScalar, h)
	return g, h
}

func dummyTXs(g, h *edwards25519.Point, numTXs int) []*transaction.Hidden {
	randBytes := make([]byte, 64)
	txList := make([]*transaction.Hidden, numTXs)
	for i := 0; i < numTXs; i++ {
		_, err := rand.Read(randBytes)
		if err != nil {
			panic(err)
		}
		sender := string(randBytes)
		_, err = rand.Read(randBytes)
		if err != nil {
			panic(err)
		}
		receiver := string(randBytes)
		amount := rand2.Int63()
		tx := &transaction.Plain{
			Sender:    sender,
			Receiver:  receiver,
			Amount:    amount,
			Timestamp: time.Now().UnixNano(),
		}
		txList[i], err = tx.Hide(uint64(i), g, h)
		if err != nil {
			panic(err)
		}
	}
	return txList
}

func Test_computeTXCommitCheck(t *testing.T) {
	lastCommit, currCommit, txList := computeTXCommitCheckSetUp(100)
	type args struct {
		lastCommit []byte
		currCommit []byte
		txList     []*transaction.Hidden
	}
	tests := []struct {
		name    string
		args    args
		want    *edwards25519.Point
		wantErr bool
	}{
		{
			name: "Test_computeTXCommitCheck",
			args: args{
				lastCommit: lastCommit.Bytes(),
				currCommit: currCommit.Bytes(),
				txList:     txList,
			},
			want:    edwards25519.NewIdentityPoint(),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := computeTXCommitCheck(tt.args.lastCommit, tt.args.currCommit, tt.args.txList)
			if (err != nil) != tt.wantErr {
				t.Errorf("computeTXCommitCheck() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got.Equal(tt.want) == 0 {
				t.Errorf("computeTXCommitCheck() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func checkAllOrgEpochSetup(numOrg, numTXs int) (orgLastCommits, orgEpochCommits, orgCurrCommits [][][]byte) {
	orgLastCommits = make([][][]byte, numOrg)
	orgEpochCommits = make([][][]byte, numOrg)
	orgCurrCommits = make([][][]byte, numOrg)
	var err error
	for i := 0; i < numOrg; i++ {
		orgLastCommits[i] = make([][]byte, 4)
		orgEpochCommits[i] = make([][]byte, 4)
		orgCurrCommits[i] = make([][]byte, 4)
		for j := 0; j < 4; j++ {
			g, h := paramSetup()
			txList := dummyTXs(g, h, numTXs)
			epochCommitPoint := edwards25519.NewIdentityPoint()
			tmp := new(edwards25519.Point)
			for _, tx := range txList {
				_, err = tmp.SetBytes(tx.Commitment)
				if err != nil {
					panic(err)
				}
				epochCommitPoint.Add(epochCommitPoint, tmp)
			}
			lastCommit, err := commitment.Commit(12345, time.Now().UnixNano(), 0, g, h)
			if err != nil {
				panic(err)
			}
			lastCommitPoint, err := new(edwards25519.Point).SetBytes(lastCommit)
			if err != nil {
				panic(err)
			}
			currCommitPoint := new(edwards25519.Point).Add(epochCommitPoint, lastCommitPoint)
			orgLastCommits[i][j] = lastCommit
			orgEpochCommits[i][j] = epochCommitPoint.Bytes()
			orgCurrCommits[i][j] = currCommitPoint.Bytes()
		}
	}
	return orgLastCommits, orgEpochCommits, orgCurrCommits
}

func TestCheckAllOrgEpoch(t *testing.T) {
	orgLastCommits, orgEpochCommits, orgCurrCommits := checkAllOrgEpochSetup(5, 100)
	type args struct {
		orgLastCommits  [][][]byte
		orgEpochCommits [][][]byte
		orgCurrCommits  [][][]byte
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{
		{
			name: "TestCheckAllOrgEpoch",
			args: args{
				orgLastCommits:  orgLastCommits,
				orgEpochCommits: orgEpochCommits,
				orgCurrCommits:  orgCurrCommits,
			},
			want:    true,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CheckAllOrgEpoch(tt.args.orgLastCommits, tt.args.orgEpochCommits, tt.args.orgCurrCommits)
			if (err != nil) != tt.wantErr {
				t.Errorf("CheckAllOrgEpoch() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("CheckAllOrgEpoch() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func checkOrgEpochSetup(numTXs int) (lastCommits, currCommits [][]byte, txLists [][]*transaction.Hidden) {
	lastCommits = make([][]byte, 4)
	currCommits = make([][]byte, 4)
	txLists = make([][]*transaction.Hidden, 4)
	for i := 0; i < 4; i++ {
		var lastCommitPoint, currCommitPoint *edwards25519.Point
		lastCommitPoint, currCommitPoint, txLists[i] = computeTXCommitCheckSetUp(numTXs)
		lastCommits[i] = lastCommitPoint.Bytes()
		currCommits[i] = currCommitPoint.Bytes()
	}
	return
}

func TestCheckOrgEpoch(t *testing.T) {
	lastCommits, currCommits, txLists := checkOrgEpochSetup(100)
	type args struct {
		lastCommits [][]byte
		currCommits [][]byte
		txLists     [][]*transaction.Hidden
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{
		{
			name: "TestCheckOrgEpoch",
			args: args{
				lastCommits: lastCommits,
				currCommits: currCommits,
				txLists:     txLists,
			},
			want:    true,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, got, err := CheckOrgEpoch(tt.args.lastCommits, tt.args.currCommits, tt.args.txLists)
			if (err != nil) != tt.wantErr {
				t.Errorf("CheckOrgEpoch() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CheckOrgEpoch() got = %v, want %v", got, tt.want)
			}
		})
	}
}
