package abi

import (
	"bytes"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// TestUnpackWithRemainderComplex verifies the remainder computation for
// nested dynamic tuples and dynamic arrays of dynamic tuples, where the
// decoder and the measurer must agree on offset bases.
func TestUnpackWithRemainderComplex(t *testing.T) {
	const nestedTuple = `[{"name":"tuple","type":"function","outputs":[
		{"type":"tuple","name":"s","components":[{"type":"uint256","name":"a"},{"type":"uint256[]","name":"b"},{"type":"tuple[]","name":"c","components":[{"name":"x", "type":"uint256"},{"name":"y","type":"uint256"}]}]},
		{"type":"tuple","name":"t","components":[{"name":"x", "type":"uint256"},{"name":"y","type":"uint256"}]},
		{"type":"uint256","name":"a"}
	]}]`
	abi, err := JSON(strings.NewReader(nestedTuple))
	if err != nil {
		t.Fatal(err)
	}
	buff := new(bytes.Buffer)
	buff.Write(common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000080"))
	buff.Write(common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000000"))
	buff.Write(common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000001"))
	buff.Write(common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000001"))
	buff.Write(common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000001"))
	buff.Write(common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000060"))
	buff.Write(common.Hex2Bytes("00000000000000000000000000000000000000000000000000000000000000c0"))
	buff.Write(common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000002"))
	buff.Write(common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000001"))
	buff.Write(common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000002"))
	buff.Write(common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000002"))
	buff.Write(common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000001"))
	buff.Write(common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000002"))
	buff.Write(common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000002"))
	buff.Write(common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000001"))

	data := buff.Bytes()
	vals, rem, err := abi.UnpackWithRemainder("tuple", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rem != 0 {
		t.Errorf("want 0 remainder for exact encoding, got %d", rem)
	}
	if len(vals) != 3 {
		t.Fatalf("want 3 values, got %d", len(vals))
	}

	// Add trailing garbage and verify the remainder is reported.
	garbage := make([]byte, 64)
	for i := range garbage {
		garbage[i] = 0xab
	}
	dataWithGarbage := append(append([]byte{}, data...), garbage...)
	_, rem, err = abi.UnpackWithRemainder("tuple", dataWithGarbage)
	if err != nil {
		t.Fatalf("unexpected error with garbage: %v", err)
	}
	if rem != len(garbage) {
		t.Errorf("want %d remainder with garbage, got %d", len(garbage), rem)
	}

	// Truncated dynamic content must fail, not return partial success.
	if _, _, err := abi.UnpackWithRemainder("tuple", data[:len(data)-1]); err == nil {
		t.Error("expected error on truncated input, got nil")
	}
}

// TestUnpackWithRemainderStaticMultiWord verifies the remainder computation
// for static multi-word types (static tuples and static arrays) that occupy
// more than one head word.
func TestUnpackWithRemainderStaticMultiWord(t *testing.T) {
	const abiJSON = `[
		{"name":"m","type":"function","outputs":[
			{"type":"uint64[3]","name":"arr"},
			{"type":"uint64","name":"x"},
			{"type":"tuple","name":"t","components":[{"type":"uint256","name":"a"},{"type":"bool","name":"b"}]},
			{"type":"uint256","name":"y"}
		]}
	]`
	abi, err := JSON(strings.NewReader(abiJSON))
	if err != nil {
		t.Fatal(err)
	}
	// arr: 3 words (9,9,9), x: 1 word (8), t: 2 words (1, true), y: 1 word (7)
	data := common.Hex2Bytes(
		"0000000000000000000000000000000000000000000000000000000000000009" +
			"0000000000000000000000000000000000000000000000000000000000000009" +
			"0000000000000000000000000000000000000000000000000000000000000009" +
			"0000000000000000000000000000000000000000000000000000000000000008" +
			"0000000000000000000000000000000000000000000000000000000000000001" +
			"0000000000000000000000000000000000000000000000000000000000000001" +
			"0000000000000000000000000000000000000000000000000000000000000007")
	vals, rem, err := abi.UnpackWithRemainder("m", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rem != 0 {
		t.Errorf("want 0 remainder, got %d", rem)
	}
	if len(vals) != 4 {
		t.Fatalf("want 4 values, got %d", len(vals))
	}
	// sanity check a couple of values
	if vals[1].(uint64) != 8 {
		t.Errorf("want x=8, got %v", vals[1])
	}
	if vals[3].(*big.Int).Cmp(big.NewInt(7)) != 0 {
		t.Errorf("want y=7, got %v", vals[3])
	}
}
