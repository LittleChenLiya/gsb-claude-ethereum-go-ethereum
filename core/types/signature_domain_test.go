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
	"bytes"
	"crypto/ecdsa"
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// signerDomainFixtures builds the fixtures used to verify the signature
// domain entry point: one key signing the same logical transfer under
// different chain IDs and transaction types.
func signerDomainFixtures(t *testing.T) (*ecdsa.PrivateKey, common.Address, map[string]*Transaction) {
	t.Helper()
	key, err := crypto.HexToECDSA("9c22ff5f21f0b81b113e63f7db6da94fedef11b2119b4088b89664fb9a3cb658")
	if err != nil {
		t.Fatal(err)
	}
	addr := crypto.PubkeyToAddress(key.PublicKey)
	to := common.HexToAddress("0x000000000000000000000000000000000000dEaD")

	chain1 := big.NewInt(1)
	chain2 := big.NewInt(2)
	signer1 := NewLondonSigner(chain1)
	signer2 := NewLondonSigner(chain2)

	// EIP-1559 transaction signed on chain 1.
	dynTx := NewTx(&DynamicFeeTx{
		ChainID:   chain1,
		Nonce:     3,
		GasTipCap: big.NewInt(1),
		GasFeeCap: big.NewInt(100),
		Gas:       21000,
		To:        &to,
		Value:     big.NewInt(1000),
		Data:      []byte("hello"),
	})
	signedDyn, err := SignTx(dynTx, signer1, key)
	if err != nil {
		t.Fatal(err)
	}

	// Cross-chain replay fixture: identical contents and the very same R/S/V
	// signature, but the envelope claims chain 2.
	v, r, s := signedDyn.RawSignatureValues()
	replayedToChain2 := NewTx(&DynamicFeeTx{
		ChainID:   new(big.Int).Set(chain2),
		Nonce:     3,
		GasTipCap: big.NewInt(1),
		GasFeeCap: big.NewInt(100),
		Gas:       21000,
		To:        &to,
		Value:     big.NewInt(1000),
		Data:      []byte("hello"),
		V:         new(big.Int).Set(v),
		R:         new(big.Int).Set(r),
		S:         new(big.Int).Set(s),
	})

	// Cross-type fixture: the chain-1 1559 signature attached to a 2930 body.
	accessTx := NewTx(&AccessListTx{
		ChainID:  new(big.Int).Set(chain1),
		Nonce:    3,
		GasPrice: big.NewInt(100),
		Gas:      21000,
		To:       &to,
		Value:    big.NewInt(1000),
		Data:     []byte("hello"),
		V:        new(big.Int).Set(v),
		R:        new(big.Int).Set(r),
		S:        new(big.Int).Set(s),
	})

	// Replay-protected and unprotected legacy transactions.
	protectedLegacy, err := SignTx(
		NewTransaction(3, to, big.NewInt(1000), 21000, big.NewInt(100), []byte("hello")),
		NewEIP155Signer(chain1), key)
	if err != nil {
		t.Fatal(err)
	}
	unprotectedLegacy, err := SignTx(
		NewTransaction(3, to, big.NewInt(1000), 21000, big.NewInt(100), []byte("hello")),
		HomesteadSigner{}, key)
	if err != nil {
		t.Fatal(err)
	}

	txs := map[string]*Transaction{
		"dynamicFeeChain1":  signedDyn,
		"dynamicFeeChain2":  replayedToChain2,
		"accessListChain1":  accessTx,
		"legacyProtected":   protectedLegacy,
		"legacyUnprotected": unprotectedLegacy,
	}
	t.Logf("sighash chain1 signer: %s", signer1.Hash(signedDyn))
	t.Logf("sighash chain2 signer: %s (same contents, different chain id)", signer2.Hash(signedDyn))
	t.Logf("sighash access-list  : %s (same signature, different tx type)", signer1.Hash(accessTx))
	return key, addr, txs
}

// TestSignatureDomainAccept checks that a properly signed transaction passes
// the domain entry point and that the reported domains agree on chain id,
// type and signed hash.
func TestSignatureDomainAccept(t *testing.T) {
	key, addr, txs := signerDomainFixtures(t)

	cases := []struct {
		name   string
		signer Signer
		tx     *Transaction
	}{
		{"dynamic fee on its own chain", NewLondonSigner(big.NewInt(1)), txs["dynamicFeeChain1"]},
		{"protected legacy on its own chain", NewEIP155Signer(big.NewInt(1)), txs["legacyProtected"]},
		{"protected legacy via modern signer", NewLondonSigner(big.NewInt(1)), txs["legacyProtected"]},
		{"unprotected legacy via homestead signer", HomesteadSigner{}, txs["legacyUnprotected"]},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			observed, expected, err := tc.tx.CheckSignatureDomain(tc.signer)
			if err != nil {
				t.Fatalf("expected domain to match, got %v (observed %s / expected %s)", err, observed, expected)
			}
			if observed.ChainID.Cmp(expected.ChainID) != 0 || observed.TxType != expected.TxType || observed.SignedOn != expected.SignedOn {
				t.Fatalf("domains differ: %s vs %s", observed, expected)
			}
			if observed.SignedOn != tc.signer.Hash(tc.tx) {
				t.Fatalf("signed hash %s != signer hash %s", observed.SignedOn, tc.signer.Hash(tc.tx))
			}
			from, err := Sender(tc.signer, tc.tx)
			if err != nil {
				t.Fatalf("sender recovery failed: %v", err)
			}
			if from != addr {
				t.Fatalf("recovered %s, want signer %s", from, addr)
			}
			t.Logf("OK [%s]: key %s -> %s", tc.name, crypto.PubkeyToAddress(key.PublicKey), observed)
		})
	}
}

// TestSignatureDomainRejectCrossChain replays the exact same signed
// transaction on a different chain and requires rejection, showing the two
// signing hashes involved.
func TestSignatureDomainRejectCrossChain(t *testing.T) {
	_, addr, txs := signerDomainFixtures(t)

	t.Run("typed tx replayed on another chain", func(t *testing.T) {
		tx := txs["dynamicFeeChain1"]
		signer1 := NewLondonSigner(big.NewInt(1))
		signer2 := NewLondonSigner(big.NewInt(2))

		observed, expected, err := tx.CheckSignatureDomain(signer2)
		if !errors.Is(err, ErrSignatureDomainChainID) {
			t.Fatalf("want ErrSignatureDomainChainID, got %v", err)
		}
		if observed.ChainID.Cmp(big.NewInt(1)) != 0 || expected.ChainID.Cmp(big.NewInt(2)) != 0 {
			t.Fatalf("unexpected chain ids: observed %s expected %s", observed.ChainID, expected.ChainID)
		}
		// Both hashes must be visible and must differ: that is the replay gap.
		ownHash := signer1.Hash(tx)
		foreignHash := signer2.Hash(tx)
		if ownHash == foreignHash {
			t.Fatal("cross-chain signing hashes unexpectedly equal")
		}
		if _, senderErr := Sender(signer2, tx); !errors.Is(senderErr, ErrInvalidChainId) {
			t.Fatalf("Sender should reject replay, got %v", senderErr)
		}
		t.Logf("REJECT cross-chain replay: chain %s vs %s", observed.ChainID, expected.ChainID)
		t.Logf("  signed hash on chain 1: %s", ownHash)
		t.Logf("  signed hash on chain 2: %s", foreignHash)
	})

	t.Run("envelope mutated to claim a foreign chain id", func(t *testing.T) {
		// The body was re-encoded for chain 2 while keeping the chain-1
		// R/S/V. Its envelope is internally consistent with chain 2, so the
		// pure domain check cannot smell anything (it does not look at the
		// signature) - but recovery over the chain-2 hash cannot yield the
		// chain-1 signer. Checking the same bytes against chain 1 rejects the
		// replay outright.
		tx := txs["dynamicFeeChain2"]
		if _, _, err := tx.CheckSignatureDomain(NewLondonSigner(big.NewInt(2))); err != nil {
			t.Fatalf("envelope is domain-consistent with chain 2, got %v", err)
		}
		recovered, err := Sender(NewLondonSigner(big.NewInt(2)), tx)
		if err != nil {
			t.Fatal(err)
		}
		if recovered == addr {
			t.Fatal("stolen signature unexpectedly recovered the original signer")
		}
		if _, _, err := tx.CheckSignatureDomain(NewLondonSigner(big.NewInt(1))); !errors.Is(err, ErrSignatureDomainChainID) {
			t.Fatalf("chain 1 must reject the foreign envelope, got %v", err)
		}
		t.Logf("REJECT forged chain-2 envelope: recovered %s instead of %s", recovered, addr)
	})

	t.Run("protected legacy tx replayed on another chain", func(t *testing.T) {
		tx := txs["legacyProtected"]
		_, _, err := tx.CheckSignatureDomain(NewEIP155Signer(big.NewInt(2)))
		if !errors.Is(err, ErrSignatureDomainChainID) {
			t.Fatalf("want ErrSignatureDomainChainID, got %v", err)
		}
		ownHash := NewEIP155Signer(big.NewInt(1)).Hash(tx)
		foreignHash := NewEIP155Signer(big.NewInt(2)).Hash(tx)
		if ownHash == foreignHash {
			t.Fatal("legacy cross-chain signing hashes unexpectedly equal")
		}
		t.Logf("REJECT legacy cross-chain replay:")
		t.Logf("  signed hash on chain 1: %s", ownHash)
		t.Logf("  signed hash on chain 2: %s", foreignHash)
	})

	t.Run("unprotected legacy tx checked against chained signer", func(t *testing.T) {
		tx := txs["legacyUnprotected"]
		_, _, err := tx.CheckSignatureDomain(NewLondonSigner(big.NewInt(1)))
		if !errors.Is(err, ErrSignatureDomainChainID) {
			t.Fatalf("want ErrSignatureDomainChainID, got %v", err)
		}
	})
}

// TestSignatureDomainRejectType moves one signature between transaction
// types and requires rejection via the signing-hash / type checks.
func TestSignatureDomainRejectType(t *testing.T) {
	_, addr, txs := signerDomainFixtures(t)
	signer1 := NewLondonSigner(big.NewInt(1))

	t.Run("1559 signature attached to 2930 tx", func(t *testing.T) {
		tx := txs["accessListChain1"]
		// The 2930 body is internally consistent with the chain-1 domain; the
		// entry point reports which hash the body really signs, and it differs
		// from the hash the reused 1559 signature was created for. Without
		// ecrecover there is no other way to spot the theft - recovery over
		// the 2930 hash simply cannot return the 1559 signer.
		observed, expected, err := tx.CheckSignatureDomain(signer1)
		if err != nil {
			t.Fatalf("2930 envelope is domain-consistent, got %v", err)
		}
		stolenFrom := signer1.Hash(txs["dynamicFeeChain1"])
		if observed.SignedOn != expected.SignedOn {
			t.Fatal("observed and expected domains should agree for the 2930 body")
		}
		if observed.SignedOn == stolenFrom {
			t.Fatal("2930 and 1559 signing hashes unexpectedly equal")
		}
		from, _ := Sender(signer1, tx)
		if from == addr {
			t.Fatal("cross-type signature unexpectedly recovered original signer")
		}
		t.Logf("REJECT signature moved type 0x02 -> 0x01:")
		t.Logf("  hash the stolen R/S/V actually signs (1559): %s", stolenFrom)
		t.Logf("  hash presented by the 2930 body             : %s", observed.SignedOn)
		t.Logf("  recovered sender                            : %s (want %s)", from, addr)
	})

	t.Run("typed tx checked against legacy-only signer", func(t *testing.T) {
		tx := txs["dynamicFeeChain1"]
		_, _, err := tx.CheckSignatureDomain(NewEIP155Signer(big.NewInt(1)))
		if !errors.Is(err, ErrSignatureDomainType) {
			t.Fatalf("want ErrSignatureDomainType, got %v", err)
		}
	})

	t.Run("signer presenting a different signing hash", func(t *testing.T) {
		// An external signer with a matching chain id but a deviating hash
		// rule is caught by the hash comparison.
		tx := txs["dynamicFeeChain1"]
		wrong := &wrongHashSigner{Signer: signer1, h: common.HexToHash("0xdeadbeef")}
		observed, expected, err := tx.CheckSignatureDomain(wrong)
		if !errors.Is(err, ErrSignatureDomainHash) {
			t.Fatalf("want ErrSignatureDomainHash, got %v", err)
		}
		if observed.SignedOn == expected.SignedOn {
			t.Fatal("signing hashes unexpectedly equal")
		}
	})
}

// wrongHashSigner wraps a signer and lies about Hash, simulating an external
// signer that defines an incompatible signing domain.
type wrongHashSigner struct {
	Signer
	h common.Hash
}

func (s *wrongHashSigner) Hash(*Transaction) common.Hash { return s.h }
func (s *wrongHashSigner) Equal(other Signer) bool       { return other == s }

// TestSignatureDomainPreservesEncoding makes sure historical transaction
// encodings are left untouched: the domain check is read-only, legacy
// transactions keep their bare RLP encoding, and typed txs keep the
// EIP-2718 envelope.
func TestSignatureDomainPreservesEncoding(t *testing.T) {
	_, _, txs := signerDomainFixtures(t)
	cases := []struct {
		name   string
		signer Signer
		tx     *Transaction
		legacy bool
	}{
		{"legacy", NewEIP155Signer(big.NewInt(1)), txs["legacyProtected"], true},
		{"dynamic fee", NewLondonSigner(big.NewInt(1)), txs["dynamicFeeChain1"], false},
		{"access list", NewLondonSigner(big.NewInt(1)), txs["accessListChain1"], false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before, err := tc.tx.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			tc.tx.CheckSignatureDomain(tc.signer)
			after, err := tc.tx.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatalf("encoding changed by domain check:\nbefore %x\nafter  %x", before, after)
			}
			if tc.legacy && before[0] <= 0x7f {
				t.Fatalf("legacy tx lost bare RLP encoding: %x", before[:1])
			}
			if !tc.legacy && before[0] != tc.tx.Type() {
				t.Fatalf("typed tx envelope prefix changed: %x", before[0])
			}
			// Round-trip stability.
			var rt Transaction
			if err := rt.UnmarshalBinary(before); err != nil {
				t.Fatal(err)
			}
			rtBytes, _ := rt.MarshalBinary()
			if !bytes.Equal(before, rtBytes) {
				t.Fatal("round-trip encoding mismatch")
			}
			t.Logf("OK: %s encoding preserved (%d bytes, type 0x%02x)", tc.name, len(before), tc.tx.Type())
		})
	}
}
