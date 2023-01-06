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
	addPoint, leftPoint, rightPoint := new(ed25519.Point), new(ed25519.Point), new(ed25519.Point)
	for i := 1; i < t.height; i++ {
		for j := 0; j < len(t.nodes[i]); j++ {
			if j<<1+1 < len(t.nodes[i-1]) {
				_, err := leftPoint.SetBytes(t.nodes[i-1][j<<1])
				if err != nil {
					return err
				}
				_, err = rightPoint.SetBytes(t.nodes[i-1][j<<1+1])
				if err != nil {
					return err
				}
				addPoint.Add(leftPoint, rightPoint)
				t.nodes[i][j] = addPoint.Bytes()
			} else {
				t.nodes[i][j] = t.nodes[i-1][j<<1]
			}
		}
	}
	t.Root = t.nodes[t.height-1][0]
	return nil
}
