// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package abi

import (
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// unpackRemainingJSON is a self-contained ABI used as a local, controllable
// fixture. Every exercised method packs deterministically so that test inputs
// are fully reproducible without external data.
const unpackRemainingJSON = `
[
	{ "type": "function", "name": "staticArgs", "outputs": [
		{ "name": "a", "type": "uint256" },
		{ "name": "b", "type": "bool" },
		{ "name": "c", "type": "address" },
		{ "name": "d", "type": "uint256[2]" }
	]},
	{ "type": "function", "name": "singleStatic", "outputs": [
		{ "name": "a", "type": "uint256" }
	]},
	{ "type": "function", "name": "dynamicArray", "outputs": [
		{ "name": "a", "type": "uint256[]" }
	]},
	{ "type": "function", "name": "bytesArg", "outputs": [
		{ "name": "a", "type": "bytes" }
	]},
	{ "type": "function", "name": "stringArg", "outputs": [
		{ "name": "a", "type": "string" }
	]},
	{ "type": "function", "name": "mixed", "outputs": [
		{ "name": "x", "type": "uint256" },
		{ "name": "y", "type": "uint256[]" },
		{ "name": "z", "type": "uint256" }
	]},
	{ "type": "function", "name": "nestedSlice", "outputs": [
		{ "name": "a", "type": "uint256[][]" }
	]},
	{ "type": "function", "name": "dynTuple", "outputs": [
		{ "name": "t", "type": "tuple", "components": [
			{ "name": "fixed", "type": "uint256[2]" },
			{ "name": "list",  "type": "uint256[]" },
			{ "name": "text",  "type": "string" }
		]}
	]},
	{ "type": "function", "name": "fixedDynArray", "outputs": [
		{ "name": "a", "type": "uint256[][2]" }
	]}
]`

func mustUnpackABI(t *testing.T) ABI {
	t.Helper()
	parsed, err := JSON(strings.NewReader(unpackRemainingJSON))
	if err != nil {
		t.Fatalf("failed to parse fixture ABI: %v", err)
	}
	return parsed
}

// garbageWord is an extra 32-byte word appended to encode "trailing garbage".
var garbageWord = common.Hex2Bytes("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")

func TestUnpackWithRemainingStatic(t *testing.T) {
	parsed := mustUnpackABI(t)
	args := parsed.Methods["staticArgs"].Outputs

	addr := common.HexToAddress("0x0102030405060708090a0b0c0d0e0f1011121314")
	packed, err := args.Pack(big.NewInt(7), true, addr, [2]*big.Int{big.NewInt(11), big.NewInt(12)})
	if err != nil {
		t.Fatalf("pack failed: %v", err)
	}
	// head slots: uint256, bool, address, uint256[2] (2 words) => 5 words
	if want := 5 * 32; len(packed) != want {
		t.Fatalf("unexpected fixture length: got %d want %d", len(packed), want)
	}

	values, remaining, err := parsed.UnpackWithRemaining("staticArgs", packed)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if remaining != 0 {
		t.Fatalf("expected no remaining bytes, got %d", remaining)
	}
	if got := values[0].(*big.Int).Int64(); got != 7 {
		t.Fatalf("a: got %d want 7", got)
	}
	if values[1].(bool) != true {
		t.Fatalf("b: got false want true")
	}
	if values[2].(common.Address) != addr {
		t.Fatalf("c: got %x want %x", values[2], addr)
	}
	arr := values[3].([2]*big.Int)
	if arr[0].Int64() != 11 || arr[1].Int64() != 12 {
		t.Fatalf("d: got %v want [11 12]", arr)
	}

	// Trailing garbage of one word must be reported verbatim.
	withGarbage := append(append([]byte{}, packed...), garbageWord...)
	values, remaining, err = parsed.UnpackWithRemaining("staticArgs", withGarbage)
	if err != nil {
		t.Fatalf("unexpected error with trailing garbage: %v", err)
	}
	if remaining != 32 {
		t.Fatalf("expected 32 remaining bytes, got %d", remaining)
	}
	if values[0].(*big.Int).Int64() != 7 {
		t.Fatalf("garbage path changed decoded value: %d", values[0])
	}

	// The legacy interface must keep working and stay byte-for-byte compatible.
	legacy, err := parsed.Unpack("staticArgs", withGarbage)
	if err != nil {
		t.Fatalf("legacy Unpack failed: %v", err)
	}
	if legacy[0].(*big.Int).Int64() != 7 {
		t.Fatalf("legacy value mismatch: %d", legacy[0])
	}
}

func TestUnpackWithRemainingDynamicArray(t *testing.T) {
	parsed := mustUnpackABI(t)
	args := parsed.Methods["dynamicArray"].Outputs

	// offset word (32) + length word (32) + 3 elements (3*32) = 160 bytes.
	packed, err := args.Pack([]*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3)})
	if err != nil {
		t.Fatalf("pack failed: %v", err)
	}
	if len(packed) != 160 {
		t.Fatalf("unexpected fixture length: got %d want 160", len(packed))
	}

	values, remaining, err := parsed.UnpackWithRemaining("dynamicArray", packed)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if remaining != 0 {
		t.Fatalf("expected 0 remaining, got %d", remaining)
	}
	got := values[0].([]*big.Int)
	if len(got) != 3 || got[0].Int64() != 1 || got[2].Int64() != 3 {
		t.Fatalf("unexpected array: %v", got)
	}

	// Append two words of tail garbage.
	withGarbage := append(append([]byte{}, packed...), garbageWord...)
	withGarbage = append(withGarbage, garbageWord...)
	values, remaining, err = parsed.UnpackWithRemaining("dynamicArray", withGarbage)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if remaining != 64 {
		t.Fatalf("expected 64 remaining bytes, got %d", remaining)
	}
	if len(values[0].([]*big.Int)) != 3 {
		t.Fatalf("garbage must not change decoded element count")
	}

	// Truncate one element word off the tail: the declared length can no longer
	// be satisfied, so decoding must fail rather than return a partial array.
	truncated := packed[:len(packed)-32]
	if values, remaining, err = parsed.UnpackWithRemaining("dynamicArray", truncated); err == nil {
		t.Fatalf("expected error for truncated dynamic array, got values=%v remaining=%d", values, remaining)
	}

	// Truncate even the length word: must also fail.
	if _, _, err := parsed.UnpackWithRemaining("dynamicArray", packed[:32]); err == nil {
		t.Fatalf("expected error when length word is missing")
	}
}

func TestUnpackWithRemainingBytesAndString(t *testing.T) {
	parsed := mustUnpackABI(t)

	// bytes: "abc" occupies one padded word after the length word => 96 bytes.
	bytesPacked, err := parsed.Methods["bytesArg"].Outputs.Pack([]byte("abc"))
	if err != nil {
		t.Fatalf("pack bytes: %v", err)
	}
	if len(bytesPacked) != 96 {
		t.Fatalf("unexpected bytes fixture length %d", len(bytesPacked))
	}
	values, remaining, err := parsed.UnpackWithRemaining("bytesArg", bytesPacked)
	if err != nil {
		t.Fatalf("unpack bytes: %v", err)
	}
	if remaining != 0 || string(values[0].([]byte)) != "abc" {
		t.Fatalf("bytes: value=%q remaining=%d", values[0], remaining)
	}

	// Trailing garbage on a bytes argument.
	withGarbage := append(append([]byte{}, bytesPacked...), garbageWord...)
	if _, remaining, err := parsed.UnpackWithRemaining("bytesArg", withGarbage); err != nil || remaining != 32 {
		t.Fatalf("bytes garbage: err=%v remaining=%d", err, remaining)
	}

	// Truncate half of the payload word of the bytes argument -> failure.
	if _, _, err := parsed.UnpackWithRemaining("bytesArg", bytesPacked[:len(bytesPacked)-16]); err == nil {
		t.Fatalf("expected error for truncated bytes payload")
	}

	// string: 40 ASCII chars => 2 payload words; total 4 words = 128 bytes.
	text := strings.Repeat("z", 40)
	strPacked, err := parsed.Methods["stringArg"].Outputs.Pack(text)
	if err != nil {
		t.Fatalf("pack string: %v", err)
	}
	if len(strPacked) != 128 {
		t.Fatalf("unexpected string fixture length %d", len(strPacked))
	}
	values, remaining, err = parsed.UnpackWithRemaining("stringArg", strPacked)
	if err != nil {
		t.Fatalf("unpack string: %v", err)
	}
	if remaining != 0 || values[0].(string) != text {
		t.Fatalf("string: value=%q remaining=%d", values[0], remaining)
	}
}

func TestUnpackWithRemainingMixed(t *testing.T) {
	// Head: uint256 x (1 word), uint256[] y (1 word), uint256 z (1 word) = 96
	// bytes of head, followed by the array tail (length + 2 elems = 96).
	parsed := mustUnpackABI(t)
	args := parsed.Methods["mixed"].Outputs

	packed, err := args.Pack(big.NewInt(5), []*big.Int{big.NewInt(9), big.NewInt(10)}, big.NewInt(6))
	if err != nil {
		t.Fatalf("pack mixed: %v", err)
	}
	if len(packed) != 192 {
		t.Fatalf("unexpected mixed fixture length: got %d want 192", len(packed))
	}
	values, remaining, err := parsed.UnpackWithRemaining("mixed", packed)
	if err != nil {
		t.Fatalf("unpack mixed: %v", err)
	}
	if remaining != 0 {
		t.Fatalf("expected 0 remaining, got %d", remaining)
	}
	if values[0].(*big.Int).Int64() != 5 || values[2].(*big.Int).Int64() != 6 {
		t.Fatalf("scalar mismatch: %v %v", values[0], values[2])
	}
	if arr := values[1].([]*big.Int); len(arr) != 2 || arr[1].Int64() != 10 {
		t.Fatalf("array mismatch: %v", arr)
	}

	// Garbage after the tail.
	withGarbage := append(append([]byte{}, packed...), garbageWord...)
	values, remaining, err = parsed.UnpackWithRemaining("mixed", withGarbage)
	if err != nil || remaining != 32 {
		t.Fatalf("mixed garbage: err=%v remaining=%d", err, remaining)
	}
	if values[2].(*big.Int).Int64() != 6 {
		t.Fatalf("trailing scalar must still decode")
	}

	// Drop the last array element: truncated dynamic parameter -> error.
	truncated := packed[:len(packed)-32]
	if _, _, err := parsed.UnpackWithRemaining("mixed", truncated); err == nil {
		t.Fatalf("expected error for truncated array in mixed layout")
	}

	// Drop all tail plus one word out of the static head: error.
	if _, _, err := parsed.UnpackWithRemaining("mixed", packed[:64]); err == nil {
		t.Fatalf("expected error for truncated static head")
	}
}

func TestUnpackWithRemainingNested(t *testing.T) {
	parsed := mustUnpackABI(t)
	args := parsed.Methods["nestedSlice"].Outputs

	// uint256[][]: outer slice with two inner slices of length 2 and 1.
	outer := [][]*big.Int{
		{big.NewInt(1), big.NewInt(2)},
		{big.NewInt(3)},
	}
	packed, err := args.Pack(outer)
	if err != nil {
		t.Fatalf("pack nested: %v", err)
	}
	values, remaining, err := parsed.UnpackWithRemaining("nestedSlice", packed)
	if err != nil {
		t.Fatalf("unpack nested: %v", err)
	}
	if remaining != 0 {
		t.Fatalf("expected 0 remaining, got %d", remaining)
	}
	got := values[0].([][]*big.Int)
	if len(got) != 2 || len(got[0]) != 2 || got[1][0].Int64() != 3 {
		t.Fatalf("nested slice mismatch: %v", got)
	}

	// One word of garbage after the deepest tail.
	withGarbage := append(append([]byte{}, packed...), garbageWord...)
	if values, remaining, err := parsed.UnpackWithRemaining("nestedSlice", withGarbage); err != nil || remaining != 32 {
		t.Fatalf("nested garbage: err=%v remaining=%d values=%v", err, remaining, values)
	}

	// Truncate the innermost element.
	truncated := packed[:len(packed)-32]
	if _, _, err := parsed.UnpackWithRemaining("nestedSlice", truncated); err == nil {
		t.Fatalf("expected error for truncated nested slice")
	}
}

func TestUnpackWithRemainingDynamicTuple(t *testing.T) {
	// A dynamic tuple containing a static multi-word field (uint256[2]) before
	// dynamic members exercises the head-cursor handling inside tuples.
	parsed := mustUnpackABI(t)
	args := parsed.Methods["dynTuple"].Outputs

	type inTuple struct {
		Fixed [2]*big.Int
		List  []*big.Int
		Text  string
	}
	in := inTuple{
		Fixed: [2]*big.Int{big.NewInt(21), big.NewInt(22)},
		List:  []*big.Int{big.NewInt(31), big.NewInt(32)},
		Text:  "hello",
	}
	packed, err := args.Pack(in)
	if err != nil {
		t.Fatalf("pack tuple: %v", err)
	}
	values, remaining, err := parsed.UnpackWithRemaining("dynTuple", packed)
	if err != nil {
		t.Fatalf("unpack tuple: %v", err)
	}
	if remaining != 0 {
		t.Fatalf("expected 0 remaining, got %d", remaining)
	}
	out := values[0].(struct {
		Fixed [2]*big.Int `json:"fixed"`
		List  []*big.Int  `json:"list"`
		Text  string      `json:"text"`
	})
	if out.Fixed[0].Int64() != 21 || len(out.List) != 2 || out.Text != "hello" {
		t.Fatalf("tuple mismatch: %+v", out)
	}

	withGarbage := append(append([]byte{}, packed...), garbageWord...)
	if _, remaining, err := parsed.UnpackWithRemaining("dynTuple", withGarbage); err != nil || remaining != 32 {
		t.Fatalf("tuple garbage: err=%v remaining=%d", err, remaining)
	}

	// Drop the last word (the padded "hello" string payload): truncated tail.
	if _, _, err := parsed.UnpackWithRemaining("dynTuple", packed[:len(packed)-32]); err == nil {
		t.Fatalf("expected error for truncated tuple tail")
	}
}

func TestUnpackWithRemainingFixedArrayOfDynamic(t *testing.T) {
	// uint256[][2]: a fixed-length array of dynamic slices.
	parsed := mustUnpackABI(t)
	args := parsed.Methods["fixedDynArray"].Outputs

	in := [2][]*big.Int{
		{big.NewInt(1)},
		{big.NewInt(2), big.NewInt(3)},
	}
	packed, err := args.Pack(in)
	if err != nil {
		t.Fatalf("pack fixed-dyn: %v", err)
	}
	values, remaining, err := parsed.UnpackWithRemaining("fixedDynArray", packed)
	if err != nil {
		t.Fatalf("unpack fixed-dyn: %v", err)
	}
	if remaining != 0 {
		t.Fatalf("expected 0 remaining, got %d", remaining)
	}
	out := values[0].([2][]*big.Int)
	if len(out[0]) != 1 || out[0][0].Int64() != 1 || len(out[1]) != 2 || out[1][1].Int64() != 3 {
		t.Fatalf("fixed-dyn mismatch: %v", out)
	}

	withGarbage := append(append([]byte{}, packed...), garbageWord...)
	if _, remaining, err := parsed.UnpackWithRemaining("fixedDynArray", withGarbage); err != nil || remaining != 32 {
		t.Fatalf("fixed-dyn garbage: err=%v remaining=%d", err, remaining)
	}

	if _, _, err := parsed.UnpackWithRemaining("fixedDynArray", packed[:len(packed)-32]); err == nil {
		t.Fatalf("expected error for truncated fixed-dyn array")
	}
}

func TestUnpackWithRemainingArgumentsAndEmpty(t *testing.T) {
	parsed := mustUnpackABI(t)

	// The Arguments-level entry reports the same remainder.
	packed, err := parsed.Methods["singleStatic"].Outputs.Pack(big.NewInt(42))
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	values, remaining, err := parsed.Methods["singleStatic"].Outputs.UnpackWithRemaining(packed)
	if err != nil || remaining != 0 || values[0].(*big.Int).Int64() != 42 {
		t.Fatalf("arguments unpack: err=%v remaining=%d values=%v", err, remaining, values)
	}

	// No arguments + empty data: empty result, zero remainder, no error.
	var empty Arguments
	if values, remaining, err := empty.UnpackWithRemaining(nil); err != nil || remaining != 0 || len(values) != 0 {
		t.Fatalf("empty args: err=%v remaining=%d len=%d", err, remaining, len(values))
	}

	// Arguments expected but data empty: error (matching legacy behaviour).
	args := parsed.Methods["singleStatic"].Outputs
	if _, _, err := args.UnpackWithRemaining(nil); err == nil {
		t.Fatalf("expected error when unpacking empty data with expected arguments")
	}
}

// FuzzUnpackWithRemainingConsistency makes sure that whenever the legacy
// Unpack succeeds, UnpackWithRemaining also succeeds and reports a remainder
// between 0 and len(data), and that canonical packs always leave zero
// remainder. It also guards against panics on arbitrary byte slices.
func FuzzUnpackWithRemainingConsistency(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 32))
	f.Add(make([]byte, 64))
	f.Add(common.Hex2Bytes("000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000001"))

	fparsed, ferr := JSON(strings.NewReader(unpackRemainingJSON))
	if ferr != nil {
		f.Fatalf("failed to parse fixture ABI: %v", ferr)
	}
	names := []string{"singleStatic", "dynamicArray", "bytesArg", "stringArg", "mixed", "nestedSlice", "dynTuple", "fixedDynArray"}
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, name := range names {
			legacy, lerr := fparsed.Unpack(name, data)
			values, remaining, rerr := fparsed.UnpackWithRemaining(name, data)
			if lerr != nil {
				if rerr == nil {
					t.Fatalf("%s: legacy failed (%v) but new succeeded", name, lerr)
				}
				continue
			}
			if rerr != nil {
				t.Fatalf("%s: legacy succeeded but new failed: %v", name, rerr)
			}
			if remaining < 0 || remaining > len(data) {
				t.Fatalf("%s: invalid remaining %d for len %d", name, remaining, len(data))
			}
			if len(values) != len(legacy) {
				t.Fatalf("%s: value count mismatch %d vs %d", name, len(values), len(legacy))
			}
			// Trimming exactly the reported unconsumed suffix must leave a
			// decoding that still succeeds with zero remainder.
			if remaining > 0 {
				consumed := len(data) - remaining
				trimValues, trimRemaining, trimErr := fparsed.UnpackWithRemaining(name, data[:consumed])
				if trimErr != nil {
					t.Fatalf("%s: trimming %d reported remaining bytes failed: %v", name, remaining, trimErr)
				}
				if trimRemaining != 0 {
					t.Fatalf("%s: trimmed input still reports %d remaining", name, trimRemaining)
				}
				if len(trimValues) != len(values) {
					t.Fatalf("%s: trimming changed value count", name)
				}
			}
		}
	})
}
