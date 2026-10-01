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

// encodedSize returns the number of bytes consumed by the (non-indexed)
// arguments from the head of the top-level encoded blob. All offsets used by
// dynamic types are relative to the start of their enclosing block, so the
// size of nested values is computed from block-relative slices.
func (arguments Arguments) encodedSize(data []byte) (int, error) {
	// cursor tracks the head section: a dynamic argument (or any other single
	// word type) occupies one word, while a static fixed array or tuple is
	// encoded in place and may occupy several words.
	cursor := 0
	consumed := 0
	for _, arg := range arguments.NonIndexed() {
		if isDynamicType(arg.Type) {
			offset, err := readOffsetWord(data, cursor)
			if err != nil {
				return 0, err
			}
			end, err := encodedValueSize(arg.Type, data, offset)
			if err != nil {
				return 0, err
			}
			if end > consumed {
				consumed = end
			}
		}
		cursor += getTypeSize(arg.Type)
	}
	if cursor > consumed {
		consumed = cursor
	}
	return consumed, nil
}

// encodedValueSize returns the end offset (relative to the start of block) of
// the value of type t whose encoding begins at block[start:].
func encodedValueSize(t Type, block []byte, start int) (int, error) {
	switch t.T {
	case StringTy, BytesTy:
		length, err := readLengthWord(block, start)
		if err != nil {
			return 0, err
		}
		// The decoder only requires the unpadded payload to be present (see
		// lengthPrefixPointsTo), so a missing final partial word is not an
		// error. Canonical encoding is word padded: account for the padding
		// when it is actually present, otherwise stop at the input end.
		requiredEnd, err := addStart(start, 32+length, len(block))
		if err != nil {
			return 0, err
		}
		end := start + 32 + pad(length)
		if end > len(block) {
			end = requiredEnd
		}
		return end, nil
	case SliceTy:
		length, err := readLengthWord(block, start)
		if err != nil {
			return 0, err
		}
		return arrayBodySize(t.Elem, length, block, start+32)
	case ArrayTy:
		if isDynamicType(*t.Elem) {
			// A fixed array of dynamic elements is itself dynamic: its block
			// starts directly with the per-element offset words.
			return arrayBodySize(t.Elem, t.Size, block, start)
		}
		// Fully static fixed array, encoded inline.
		return addStart(start, getTypeSize(t), len(block))
	case TupleTy:
		if !isDynamicType(t) {
			return start + getTypeSize(t), nil
		}
		return tupleBodySize(t.TupleElems, block, start)
	default:
		// Every atomic static type occupies a single 32-byte word.
		return start + 32, nil
	}
}

// tupleBodySize returns the end offset of a dynamic tuple whose block starts
// at block[start:].
func tupleBodySize(elems []*Type, block []byte, start int) (int, error) {
	// The head section reserves the in-place size of every field: a single
	// word for ordinary types, but possibly several words for a static fixed
	// array or nested static tuple.
	headSize := 0
	for _, elem := range elems {
		headSize += getTypeSize(*elem)
	}
	end, err := addStart(start, headSize, len(block))
	if err != nil {
		return 0, err
	}
	headCursor := 0
	for _, elem := range elems {
		if isDynamicType(*elem) {
			offset, err := readOffsetWord(block, start+headCursor)
			if err != nil {
				return 0, err
			}
			elemEnd, err := encodedValueSize(*elem, block, start+offset)
			if err != nil {
				return 0, err
			}
			if elemEnd > end {
				end = elemEnd
			}
		}
		headCursor += getTypeSize(*elem)
	}
	return end, nil
}

// arrayBodySize returns the end offset of an array/slice body containing
// length elements of element type elem, whose head section starts at
// block[start:].
func arrayBodySize(elem *Type, length int, block []byte, start int) (int, error) {
	if !isDynamicType(*elem) {
		// Static elements are packed inline without offset words.
		return addStart(start, length*getTypeSize(*elem), len(block))
	}
	end, err := addStart(start, length*32, len(block))
	if err != nil {
		return 0, err
	}
	for i := 0; i < length; i++ {
		offset, err := readOffsetWord(block, start+i*32)
		if err != nil {
			return 0, err
		}
		elemEnd, err := encodedValueSize(*elem, block, start+offset)
		if err != nil {
			return 0, err
		}
		if elemEnd > end {
			end = elemEnd
		}
	}
	return end, nil
}

// readLengthWord reads the 32-byte big-endian length word at block[pos:].
func readLengthWord(block []byte, pos int) (int, error) {
	if pos < 0 || pos+32 > len(block) {
		return 0, fmt.Errorf("abi: cannot read length word at offset %d: input length %d", pos, len(block))
	}
	lengthBig := new(big.Int).SetBytes(block[pos : pos+32])
	if !lengthBig.IsUint64() {
		return 0, fmt.Errorf("abi: invalid array/bytes length: %v", lengthBig)
	}
	length := lengthBig.Uint64()
	// Guard against absurd lengths before any derived offset is computed.
	if length > uint64(len(block)) {
		return 0, fmt.Errorf("abi: declared length %d exceeds input length %d", length, len(block))
	}
	return int(length), nil
}

// readOffsetWord reads the 32-byte big-endian offset word at block[pos:].
func readOffsetWord(block []byte, pos int) (int, error) {
	if pos < 0 || pos+32 > len(block) {
		return 0, fmt.Errorf("abi: cannot read offset word at offset %d: input length %d", pos, len(block))
	}
	offsetBig := new(big.Int).SetBytes(block[pos : pos+32])
	if !offsetBig.IsUint64() {
		return 0, fmt.Errorf("abi: offset too large: %v", offsetBig)
	}
	offset := offsetBig.Uint64()
	if offset > uint64(len(block)) {
		return 0, fmt.Errorf("abi: offset %d exceeds input length %d", offset, len(block))
	}
	return int(offset), nil
}

// pad rounds n up to the next multiple of 32.
func pad(n int) int {
	return (n + 31) / 32 * 32
}

// addStart returns start+size, guarding against integer overflow and against
// the resulting region running past the block boundary.
func addStart(start, size, blockLen int) (int, error) {
	if size < 0 || start > blockLen-size {
		return 0, fmt.Errorf("abi: encoded region [start=%d, size=%d] exceeds input length %d", start, size, blockLen)
	}
	return start + size, nil
}
