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

// TestUnpackWithRemainder exercises the remainder-reporting decoder with
// fully controlled fixtures: static parameters, dynamic arrays, trailing
// garbage and truncated inputs. It verifies both the decoded values and the
// number of unconsumed bytes, and ensures truncated dynamic inputs still fail
// rather than returning partial success.
func TestUnpackWithRemainder(t *testing.T) {
	const abiJSON = `[
		{"name":"single","type":"function","outputs":[{"name":"a","type":"uint256"}]},
		{"name":"multiStatic","type":"function","outputs":[{"name":"a","type":"uint256"},{"name":"b","type":"bool"},{"name":"c","type":"address"}]},
		{"name":"uintSlice","type":"function","outputs":[{"name":"a","type":"uint256[]"}]},
		{"name":"stringSlice","type":"function","outputs":[{"name":"a","type":"string[]"}]},
		{"name":"bytesOut","type":"function","outputs":[{"name":"a","type":"bytes"}]},
		{"name":"stringOut","type":"function","outputs":[{"name":"a","type":"string"}]}
	]`
	abi, err := JSON(strings.NewReader(abiJSON))
	if err != nil {
		t.Fatal(err)
	}
	pack := func(name string, args ...any) []byte {
		t.Helper()
		data, err := abi.Methods[name].Outputs.Pack(args...)
		if err != nil {
			t.Fatalf("pack %s: %v", name, err)
		}
		return data
	}
	garbage := common.Hex2Bytes("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")

	addr := common.HexToAddress("0x0000000000000000000000000000000000000002")
	uintSlice := []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3)}
	stringSlice := []string{"ethereum", "go-ethereum"}
	bytesVal := []byte("hello")

	tests := []struct {
		name    string
		method  string
		data    []byte
		wantRem int
		wantErr bool
		check   func(t *testing.T, vals []any)
	}{
		{
			name:    "single uint256 (static)",
			method:  "single",
			data:    pack("single", big.NewInt(42)),
			wantRem: 0,
			check: func(t *testing.T, vals []any) {
				if len(vals) != 1 {
					t.Fatalf("want 1 value, got %d", len(vals))
				}
				if vals[0].(*big.Int).Cmp(big.NewInt(42)) != 0 {
					t.Errorf("want 42, got %v", vals[0])
				}
			},
		},
		{
			name:    "multiple static params",
			method:  "multiStatic",
			data:    pack("multiStatic", big.NewInt(7), true, addr),
			wantRem: 0,
			check: func(t *testing.T, vals []any) {
				if len(vals) != 3 {
					t.Fatalf("want 3 values, got %d", len(vals))
				}
				if vals[0].(*big.Int).Cmp(big.NewInt(7)) != 0 {
					t.Errorf("want 7, got %v", vals[0])
				}
				if vals[1].(bool) != true {
					t.Errorf("want true, got %v", vals[1])
				}
				if vals[2].(common.Address) != addr {
					t.Errorf("want %x, got %x", addr, vals[2])
				}
			},
		},
		{
			name:    "dynamic uint256[]",
			method:  "uintSlice",
			data:    pack("uintSlice", uintSlice),
			wantRem: 0,
			check: func(t *testing.T, vals []any) {
				if len(vals) != 1 {
					t.Fatalf("want 1 value, got %d", len(vals))
				}
				got := vals[0].([]*big.Int)
				if len(got) != len(uintSlice) {
					t.Fatalf("want %d elements, got %d", len(uintSlice), len(got))
				}
				for i := range uintSlice {
					if got[i].Cmp(uintSlice[i]) != 0 {
						t.Errorf("element %d: want %v, got %v", i, uintSlice[i], got[i])
					}
				}
			},
		},
		{
			name:    "dynamic string[]",
			method:  "stringSlice",
			data:    pack("stringSlice", stringSlice),
			wantRem: 0,
			check: func(t *testing.T, vals []any) {
				if len(vals) != 1 {
					t.Fatalf("want 1 value, got %d", len(vals))
				}
				got := vals[0].([]string)
				if len(got) != len(stringSlice) {
					t.Fatalf("want %d elements, got %d", len(stringSlice), len(got))
				}
				for i := range stringSlice {
					if got[i] != stringSlice[i] {
						t.Errorf("element %d: want %q, got %q", i, stringSlice[i], got[i])
					}
				}
			},
		},
		{
			name:    "dynamic bytes",
			method:  "bytesOut",
			data:    pack("bytesOut", bytesVal),
			wantRem: 0,
			check: func(t *testing.T, vals []any) {
				if len(vals) != 1 {
					t.Fatalf("want 1 value, got %d", len(vals))
				}
				got := vals[0].([]byte)
				if string(got) != string(bytesVal) {
					t.Errorf("want %q, got %q", bytesVal, got)
				}
			},
		},
		{
			name:    "dynamic string",
			method:  "stringOut",
			data:    pack("stringOut", "hello"),
			wantRem: 0,
			check: func(t *testing.T, vals []any) {
				if len(vals) != 1 {
					t.Fatalf("want 1 value, got %d", len(vals))
				}
				if vals[0].(string) != "hello" {
					t.Errorf("want hello, got %q", vals[0])
				}
			},
		},
		{
			name:    "static with trailing garbage",
			method:  "single",
			data:    append(append([]byte{}, pack("single", big.NewInt(42))...), garbage...),
			wantRem: len(garbage),
			check: func(t *testing.T, vals []any) {
				if len(vals) != 1 || vals[0].(*big.Int).Cmp(big.NewInt(42)) != 0 {
					t.Errorf("unexpected values: %v", vals)
				}
			},
		},
		{
			name:    "dynamic array with trailing garbage",
			method:  "uintSlice",
			data:    append(append([]byte{}, pack("uintSlice", uintSlice)...), garbage...),
			wantRem: len(garbage),
			check: func(t *testing.T, vals []any) {
				if len(vals) != 1 {
					t.Fatalf("want 1 value, got %d", len(vals))
				}
				if len(vals[0].([]*big.Int)) != len(uintSlice) {
					t.Errorf("unexpected slice length: %d", len(vals[0].([]*big.Int)))
				}
			},
		},
		{
			name:    "truncated static input",
			method:  "single",
			data:    pack("single", big.NewInt(42))[:16],
			wantErr: true,
		},
		{
			name:    "truncated dynamic bytes (partial length)",
			method:  "bytesOut",
			data:    pack("bytesOut", bytesVal)[:40],
			wantErr: true,
		},
		{
			name:    "truncated dynamic bytes (partial data)",
			method:  "bytesOut",
			data:    pack("bytesOut", bytesVal)[:80],
			wantErr: true,
		},
		{
			name:    "truncated dynamic array",
			method:  "uintSlice",
			data:    pack("uintSlice", uintSlice)[:100],
			wantErr: true,
		},
		{
			name:    "truncated dynamic string array",
			method:  "stringSlice",
			data:    pack("stringSlice", stringSlice)[:120],
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			vals, rem, err := abi.UnpackWithRemainder(tc.method, tc.data)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got values=%v remainder=%d", vals, rem)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if rem != tc.wantRem {
				t.Errorf("remainder: want %d, got %d", tc.wantRem, rem)
			}
			if tc.check != nil {
				tc.check(t, vals)
			}
			// The default decoder must still return the same values.
			defaultVals, defaultErr := abi.Unpack(tc.method, tc.data)
			if defaultErr != nil {
				t.Fatalf("default Unpack failed: %v", defaultErr)
			}
			if len(defaultVals) != len(vals) {
				t.Errorf("default Unpack returned %d values, want %d", len(defaultVals), len(vals))
			}
		})
	}
}

// TestUnpackWithRemainderEmpty ensures the remainder decoder behaves like the
// default decoder for empty inputs.
func TestUnpackWithRemainderEmpty(t *testing.T) {
	const abiJSON = `[{"name":"m","type":"function","outputs":[]}]`
	abi, err := JSON(strings.NewReader(abiJSON))
	if err != nil {
		t.Fatal(err)
	}
	vals, rem, err := abi.UnpackWithRemainder("m", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(vals) != 0 {
		t.Errorf("want 0 values, got %v", vals)
	}
	if rem != 0 {
		t.Errorf("want 0 remainder, got %d", rem)
	}
}
