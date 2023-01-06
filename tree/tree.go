package tree

import (
	"encoding/hex"

	ed25519 "filippo.io/edwards25519"
	"github.com/auti-project/auti-core/transaction"
)

// Tree is the struct for verifiable transaction tree
type Tree struct {
	Root    []byte
	nodes   [][][]byte
	leafMap map[string]int
	height  int
}

// New creates a new tree for the input hidden transaction list
func New(txList []*transaction.Hidden) (*Tree, error) {
	t := &Tree{
		leafMap: make(map[string]int),
	}
	t.init(txList)
	err := t.compute()
	if err != nil {
		return nil, err
	}
	return t, nil
}

func (t *Tree) init(txList []*transaction.Hidden) {
	txLen := len(txList)
	t.height = calHeight(txLen)
	t.nodes = make([][][]byte, t.height)
	// generate leaves
	t.nodes[0] = make([][]byte, txLen)
	for i := 0; i < txLen; i++ {
		t.nodes[0][i] = txList[i].Commitment
		t.leafMap[hex.EncodeToString(txList[i].Commitment)] = i

	}
	// make the slices for other levels
	nodeLen := txLen
	for i := 1; i < t.height; i++ {
		nodeLen = (nodeLen + 1) / 2
		t.nodes[i] = make([][]byte, nodeLen)
	}
}

func calHeight(txLen int) int {
	height := 1
	for txLen > 1 {
		txLen = (txLen + 1) / 2
		height++
	}
	return height
}

func (t *Tree) compute() error {
	points := make([]*ed25519.Point, len(t.nodes[0]))
	for i := 0; i < len(t.nodes[0]); i++ {
		points[i] = new(ed25519.Point)
		if _, err := points[i].SetBytes(t.nodes[0][i]); err != nil {
			return err
		}
	}
	gap := 1
	for i := 1; i < t.height; i++ {
		for j := 0; j < len(t.nodes[i]); j++ {
			if j<<i+gap < len(points) {
				points[j<<i].Add(points[j<<i], points[j<<i+gap])
			}
			t.nodes[i][j] = points[j<<i].Bytes()
		}
		gap <<= 1
	}
	t.Root = t.nodes[t.height-1][0]
	return nil
}
