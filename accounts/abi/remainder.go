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
	"fmt"
	"math/big"
)

// consumed returns the number of bytes of data that are occupied by the
// encoded arguments. It mirrors the layout logic used while decoding but only
// reads the length/offset words, so it must only be called after a successful
// decode.
func (arguments Arguments) consumed(data []byte) (int, error) {
	maxEnd := 0
	headPos := 0
	virtualArgs := 0
	for _, arg := range arguments {
		if arg.Indexed {
			continue
		}
		end, err := measureAt(arg.Type, data, 0, (headPos+virtualArgs)*32)
		if err != nil {
			return 0, err
		}
		if end > maxEnd {
			maxEnd = end
		}
		if arg.Type.T == ArrayTy && !isDynamicType(arg.Type) {
			// Static arrays are encoded inline, just like static tuples, so
			// they occupy more than one word in the head.
			virtualArgs += getTypeSize(arg.Type)/32 - 1
		} else if arg.Type.T == TupleTy && !isDynamicType(arg.Type) {
			virtualArgs += getTypeSize(arg.Type)/32 - 1
		}
		headPos++
	}
	return maxEnd, nil
}

// measureAt returns the offset (relative to base) immediately past the region
// occupied by an encoding of t whose head word starts at headPos. Offsets
// embedded in the encoding are interpreted relative to base.
func measureAt(t Type, data []byte, base, headPos int) (int, error) {
	if isDynamicType(t) {
		wordPos := base + headPos
		if wordPos+32 > len(data) {
			return 0, fmt.Errorf("abi: cannot measure dynamic type: offset word at %d would go over slice boundary (len=%d)", wordPos, len(data))
		}
		off := new(big.Int).SetBytes(data[wordPos : wordPos+32])
		if off.BitLen() > 63 {
			return 0, fmt.Errorf("abi: offset larger than int64: %v", off)
		}
		contentStart := base + int(off.Uint64())
		return measureContent(t, data, contentStart)
	}
	// Static types are encoded inline and occupy getTypeSize(t) bytes.
	end := headPos + getTypeSize(t)
	if base+end > len(data) {
		return 0, fmt.Errorf("abi: cannot measure static type: end %d would go over slice boundary (len=%d)", base+end, len(data))
	}
	return end, nil
}

// measureContent returns the offset immediately past the dynamic content of an
// encoding of t that starts at contentStart.
func measureContent(t Type, data []byte, contentStart int) (int, error) {
	switch t.T {
	case StringTy, BytesTy:
		if contentStart+32 > len(data) {
			return 0, fmt.Errorf("abi: cannot measure %s: length word at %d would go over slice boundary (len=%d)", t.stringKind, contentStart, len(data))
		}
		length := new(big.Int).SetBytes(data[contentStart : contentStart+32])
		if length.BitLen() > 63 {
			return 0, fmt.Errorf("abi: length larger than int64: %v", length)
		}
		end := contentStart + 32 + padTo32(int(length.Uint64()))
		if end > len(data) {
			return 0, fmt.Errorf("abi: cannot measure %s: end %d would go over slice boundary (len=%d)", t.stringKind, end, len(data))
		}
		return end, nil
	case SliceTy:
		if contentStart+32 > len(data) {
			return 0, fmt.Errorf("abi: cannot measure %s: length word at %d would go over slice boundary (len=%d)", t.stringKind, contentStart, len(data))
		}
		nBig := new(big.Int).SetBytes(data[contentStart : contentStart+32])
		if nBig.BitLen() > 63 {
			return 0, fmt.Errorf("abi: length larger than int64: %v", nBig)
		}
		n := int(nBig.Uint64())
		if isDynamicType(*t.Elem) {
			// The elements are encoded as offset words followed by their
			// contents. The offsets are relative to the start of the offset
			// words (i.e. right after the length word), matching the decoder
			// which resolves element offsets against output[begin:] where
			// begin points just past the length word.
			elemBase := contentStart + 32
			maxEnd := elemBase
			for i := 0; i < n; i++ {
				end, err := measureAt(*t.Elem, data, elemBase, i*32)
				if err != nil {
					return 0, err
				}
				if end > maxEnd {
					maxEnd = end
				}
			}
			return maxEnd, nil
		}
		// Static elements are packed inline.
		end := contentStart + 32 + n*getTypeSize(*t.Elem)
		if end > len(data) {
			return 0, fmt.Errorf("abi: cannot measure %s: end %d would go over slice boundary (len=%d)", t.stringKind, end, len(data))
		}
		return end, nil
	case ArrayTy:
		// A fixed-size array with dynamic elements: k offset words followed by
		// the element contents; offsets are relative to the start of the array.
		maxEnd := contentStart
		for i := 0; i < t.Size; i++ {
			end, err := measureAt(*t.Elem, data, contentStart, i*32)
			if err != nil {
				return 0, err
			}
			if end > maxEnd {
				maxEnd = end
			}
		}
		return maxEnd, nil
	case TupleTy:
		// A dynamic tuple: the element heads start at contentStart.
		maxEnd := contentStart
		headPos := 0
		virtualArgs := 0
		for _, elem := range t.TupleElems {
			end, err := measureAt(*elem, data, contentStart, (headPos+virtualArgs)*32)
			if err != nil {
				return 0, err
			}
			if end > maxEnd {
				maxEnd = end
			}
			if elem.T == ArrayTy && !isDynamicType(*elem) {
				virtualArgs += getTypeSize(*elem)/32 - 1
			} else if elem.T == TupleTy && !isDynamicType(*elem) {
				virtualArgs += getTypeSize(*elem)/32 - 1
			}
			headPos++
		}
		return maxEnd, nil
	default:
		return 0, fmt.Errorf("abi: cannot measure dynamic type %v", t.T)
	}
}

// padTo32 returns the number of bytes needed to pad n to a multiple of 32.
func padTo32(n int) int {
	return (n + 31) / 32 * 32
}
