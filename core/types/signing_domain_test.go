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

package types

import (
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// signingDomainFixture builds a legacy transaction and an EIP-1559 transaction
// with identical fields, both signed on the given chain with the same key.
func signingDomainFixture(t *testing.T, chainID *big.Int) (addr common.Address, legacy, dynamic *Transaction) {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	addr = crypto.PubkeyToAddress(key.PublicKey)

	legacy, err = SignTx(NewTx(&LegacyTx{
		Nonce:    0,
		To:       &addr,
		Value:    big.NewInt(1),
		Gas:      21000,
		GasPrice: big.NewInt(1_000_000_000),
	}), NewEIP155Signer(chainID), key)
	if err != nil {
		t.Fatal(err)
	}

	dynamic, err = SignTx(NewTx(&DynamicFeeTx{
		ChainID:   chainID,
		Nonce:     0,
		GasTipCap: big.NewInt(1_000_000_000),
		GasFeeCap: big.NewInt(2_000_000_000),
		Gas:       21000,
		To:        &addr,
		Value:     big.NewInt(1),
	}), NewLondonSigner(chainID), key)
	if err != nil {
		t.Fatal(err)
	}
	return addr, legacy, dynamic
}

// TestCheckSigningDomain verifies the signing domain check entry: chain ID,
// type and to-be-signed hash are reported, and cross-chain replay is rejected.
func TestCheckSigningDomain(t *testing.T) {
	chain1, chain2 := big.NewInt(1), big.NewInt(2)
	addr, legacy, dynamic := signingDomainFixture(t, chain1)

	checks := []struct {
		name    string
		tx      *Transaction
		chainID *big.Int
		wantErr error
	}{
		{"legacy signed on chain 1, checked against chain 1", legacy, chain1, nil},
		{"legacy signed on chain 1, checked against chain 2", legacy, chain2, ErrInvalidChainId},
		{"dynamic signed on chain 1, checked against chain 1", dynamic, chain1, nil},
		{"dynamic signed on chain 1, checked against chain 2", dynamic, chain2, ErrInvalidChainId},
	}
	for _, tc := range checks {
		domain, err := tc.tx.CheckSigningDomain(tc.chainID)
		t.Logf("%s: domain={chainID: %d type: %d sigHash: %x} err: %v",
			tc.name, domain.ChainID, domain.Type, domain.SigHash, err)
		if !errors.Is(err, tc.wantErr) {
			t.Fatalf("%s: got err %v, want %v", tc.name, err, tc.wantErr)
		}
		if err == nil && domain.ChainID.Cmp(tc.chainID) != 0 {
			t.Fatalf("%s: domain chain id %d does not match expected %d", tc.name, domain.ChainID, tc.chainID)
		}
	}

	// The to-be-signed hash must differ across chains and across types.
	d1, err := legacy.CheckSigningDomain(chain1)
	if err != nil {
		t.Fatal(err)
	}
	d2, _ := legacy.CheckSigningDomain(chain2) // error is expected; hash is still reported
	d3, err := dynamic.CheckSigningDomain(chain1)
	if err != nil {
		t.Fatal(err)
	}
	if d1.SigHash == d2.SigHash {
		t.Fatal("legacy sig hash must differ across chains")
	}
	if d1.SigHash == d3.SigHash {
		t.Fatal("legacy and dynamic sig hash must differ even with identical fields")
	}
	if d1.Type != LegacyTxType || d3.Type != DynamicFeeTxType {
		t.Fatalf("unexpected types: %d %d", d1.Type, d3.Type)
	}
	t.Logf("sigHash(legacy, chain 1) = %x", d1.SigHash)
	t.Logf("sigHash(legacy, chain 2) = %x", d2.SigHash)
	t.Logf("sigHash(dynamic, chain 1) = %x", d3.SigHash)

	// A signature produced for chain 1 must not recover the signer over the
	// chain 2 hash, even if the chain id check were bypassed.
	if got := recoverOverHash(t, d2.SigHash, legacy, chain1); got == addr {
		t.Fatal("cross-chain signature replay unexpectedly recovered the signer")
	} else {
		t.Logf("cross-chain recovery over chain 2 hash => %x (not the signer)", got)
	}

	// Cross-type replay: attach the legacy signature to a dynamic transaction
	// and recover over the dynamic hash. It must not recover the signer.
	lv, lr, ls := legacy.RawSignatureValues()
	recid := byte(lv.Uint64() - 37 - 2*chain1.Uint64()) // EIP-155 V = recid + 35 + 2*chainID
	crossType := NewTx(&DynamicFeeTx{
		ChainID:   chain1,
		Nonce:     0,
		GasTipCap: big.NewInt(1_000_000_000),
		GasFeeCap: big.NewInt(2_000_000_000),
		Gas:       21000,
		To:        &addr,
		Value:     big.NewInt(1),
	})
	crossType.inner.(*DynamicFeeTx).V = big.NewInt(int64(recid))
	crossType.inner.(*DynamicFeeTx).R = new(big.Int).Set(lr)
	crossType.inner.(*DynamicFeeTx).S = new(big.Int).Set(ls)
	ctDomain, err := crossType.CheckSigningDomain(chain1)
	if err != nil {
		t.Fatalf("cross-type tx should match the chain domain: %v", err)
	}
	if got := recoverOverHash(t, ctDomain.SigHash, crossType, chain1); got == addr {
		t.Fatal("cross-type signature replay unexpectedly recovered the signer")
	} else {
		t.Logf("cross-type recovery over dynamic hash => %x (not the signer)", got)
	}

	// Sanity: the genuine dynamic signature recovers the signer.
	if got := recoverOverHash(t, d3.SigHash, dynamic, chain1); got != addr {
		t.Fatalf("genuine signature recovered %x, want %x", got, addr)
	}
}

// TestCheckSigningDomainUnprotectedLegacy verifies that historical
// pre-EIP-155 transactions keep their encoding: they carry no chain ID and are
// accepted on every chain, reporting a zero chain ID.
func TestCheckSigningDomainUnprotectedLegacy(t *testing.T) {
	key, _ := crypto.GenerateKey()
	addr := crypto.PubkeyToAddress(key.PublicKey)

	tx, err := SignTx(NewTx(&LegacyTx{
		Nonce:    0,
		To:       &addr,
		Value:    big.NewInt(1),
		Gas:      21000,
		GasPrice: big.NewInt(1_000_000_000),
	}), HomesteadSigner{}, key)
	if err != nil {
		t.Fatal(err)
	}
	if tx.Protected() {
		t.Fatal("expected unprotected legacy transaction")
	}

	for _, chainID := range []*big.Int{nil, big.NewInt(1), big.NewInt(2)} {
		domain, err := tx.CheckSigningDomain(chainID)
		if err != nil {
			t.Fatalf("unexpected error for chain %v: %v", chainID, err)
		}
		if domain.ChainID.Sign() != 0 {
			t.Fatalf("unprotected legacy must report zero chain id, got %d", domain.ChainID)
		}
		if domain.Type != LegacyTxType {
			t.Fatalf("unexpected type %d", domain.Type)
		}
		t.Logf("unprotected legacy checked against chain %v: sigHash %x", chainID, domain.SigHash)
	}
}

// TestCheckSigningDomainUnknownType verifies that transactions with an unknown
// type byte are rejected.
func TestCheckSigningDomainUnknownType(t *testing.T) {
	tx := NewTx(&LegacyTx{})
	tx.inner = &unknownTx{}
	if _, err := tx.CheckSigningDomain(big.NewInt(1)); !errors.Is(err, ErrTxTypeNotSupported) {
		t.Fatalf("expected ErrTxTypeNotSupported, got %v", err)
	}
}

// recoverOverHash recovers the sender address from the transaction signature
// over the given hash.
func recoverOverHash(t *testing.T, hash common.Hash, tx *Transaction, chainID *big.Int) common.Address {
	t.Helper()
	v, r, s := tx.RawSignatureValues()
	sig := make([]byte, crypto.SignatureLength)
	rb, sb := r.Bytes(), s.Bytes()
	copy(sig[32-len(rb):32], rb)
	copy(sig[64-len(sb):64], sb)
	if tx.Type() == LegacyTxType && tx.Protected() {
		// V encodes the recovery id: V = recid + 35 + 2*chainID.
		sig[64] = byte(v.Uint64() - 35 - 2*chainID.Uint64())
	} else {
		sig[64] = byte(v.Uint64())
	}
	pub, err := crypto.SigToPub(hash[:], sig)
	if err != nil {
		return common.Address{}
	}
	return crypto.PubkeyToAddress(*pub)
}

// unknownTx is a TxData with an unsupported type byte.
type unknownTx struct {
	LegacyTx
}

func (tx *unknownTx) txType() byte { return 0xff }
