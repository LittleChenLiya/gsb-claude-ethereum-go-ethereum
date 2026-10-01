// Copyright 2026 The go-ethereum Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

// signingdomain is a acceptance tool for the transaction signing domain check.
// It builds fixtures of the same signature on two chains and different
// transaction types, then verifies that cross-chain and cross-type replay are
// rejected and that the to-be-signed hashes differ.
package main

import (
	"flag"
	"fmt"
	"math/big"
	"os"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

var (
	chainA = flag.Int64("chain-a", 1, "first chain id")
	chainB = flag.Int64("chain-b", 2, "second chain id")
)

func main() {
	flag.Parse()
	if err := run(big.NewInt(*chainA), big.NewInt(*chainB)); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(chainA, chainB *big.Int) error {
	key, err := crypto.GenerateKey()
	if err != nil {
		return err
	}
	signer := crypto.PubkeyToAddress(key.PublicKey)

	// Build a legacy transaction and an EIP-1559 transaction with identical
	// fields, both signed on chain A with the same key.
	legacy, err := types.SignTx(types.NewTx(&types.LegacyTx{
		Nonce:    0,
		To:       &signer,
		Value:    big.NewInt(1),
		Gas:      21000,
		GasPrice: big.NewInt(1_000_000_000),
	}), types.NewEIP155Signer(chainA), key)
	if err != nil {
		return err
	}
	dynamic, err := types.SignTx(types.NewTx(&types.DynamicFeeTx{
		ChainID:   chainA,
		Nonce:     0,
		GasTipCap: big.NewInt(1_000_000_000),
		GasFeeCap: big.NewInt(2_000_000_000),
		Gas:       21000,
		To:        &signer,
		Value:     big.NewInt(1),
	}), types.NewLondonSigner(chainA), key)
	if err != nil {
		return err
	}

	fmt.Printf("signer address: %x\n", signer)
	fmt.Printf("chain A: %d  chain B: %d\n\n", chainA, chainB)

	// Check the signing domain of each transaction against both chains.
	for _, tc := range []struct {
		name string
		tx   *types.Transaction
	}{
		{"legacy (type 0)", legacy},
		{"dynamic (type 2)", dynamic},
	} {
		for _, chainID := range []*big.Int{chainA, chainB} {
			domain, err := tc.tx.CheckSigningDomain(chainID)
			status := "OK"
			if err != nil {
				status = "REJECT"
			}
			fmt.Printf("[%s] %s checked against chain %d: chainID=%d type=%d sigHash=%x err=%v\n",
				status, tc.name, chainID, domain.ChainID, domain.Type, domain.SigHash, err)
		}
		fmt.Println()
	}

	// Show that the to-be-signed hash differs across chains and types.
	dA1, _ := legacy.CheckSigningDomain(chainA)
	dB1, _ := legacy.CheckSigningDomain(chainB)
	dA2, _ := dynamic.CheckSigningDomain(chainA)
	fmt.Printf("sigHash(legacy, chain A) = %x\n", dA1.SigHash)
	fmt.Printf("sigHash(legacy, chain B) = %x  (differs from chain A: %v)\n", dB1.SigHash, dA1.SigHash != dB1.SigHash)
	fmt.Printf("sigHash(dynamic, chain A) = %x  (differs from legacy: %v)\n", dA2.SigHash, dA1.SigHash != dA2.SigHash)
	fmt.Println()

	// Show that a signature produced for chain A does not recover the signer
	// over the chain B hash, and that the legacy signature does not recover
	// the signer over the dynamic hash.
	if got := recoverOverHash(dB1.SigHash, legacy, chainA); got != signer {
		fmt.Printf("cross-chain replay: recovered %x (not the signer) => rejected\n", got)
	} else {
		return fmt.Errorf("cross-chain replay unexpectedly recovered the signer")
	}
	// Attach the legacy signature to a dynamic transaction and recover over
	// the dynamic hash. It must not recover the signer.
	lv, lr, ls := legacy.RawSignatureValues()
	recid := byte(lv.Uint64() - 35 - 2*chainA.Uint64()) // EIP-155 V = recid + 35 + 2*chainID
	crossType, err := types.NewTx(&types.DynamicFeeTx{
		ChainID:   chainA,
		Nonce:     0,
		GasTipCap: big.NewInt(1_000_000_000),
		GasFeeCap: big.NewInt(2_000_000_000),
		Gas:       21000,
		To:        &signer,
		Value:     big.NewInt(1),
	}).WithSignature(types.NewLondonSigner(chainA), legacySigToBytes(lr, ls, recid))
	if err != nil {
		return err
	}
	ctDomain, err := crossType.CheckSigningDomain(chainA)
	if err != nil {
		return fmt.Errorf("cross-type tx should match the chain domain: %v", err)
	}
	if got := recoverOverHash(ctDomain.SigHash, crossType, chainA); got != signer {
		fmt.Printf("cross-type replay:  recovered %x (not the signer) => rejected\n", got)
	} else {
		return fmt.Errorf("cross-type replay unexpectedly recovered the signer")
	}
	return nil
}

// legacySigToBytes packs the legacy R, S values and recovery id into the
// [R || S || V] signature format.
func legacySigToBytes(r, s *big.Int, recid byte) []byte {
	sig := make([]byte, crypto.SignatureLength)
	rb, sb := r.Bytes(), s.Bytes()
	copy(sig[32-len(rb):32], rb)
	copy(sig[64-len(sb):64], sb)
	sig[64] = recid
	return sig
}

// recoverOverHash recovers the sender address from the transaction signature
// over the given hash.
func recoverOverHash(hash common.Hash, tx *types.Transaction, chainID *big.Int) common.Address {
	v, r, s := tx.RawSignatureValues()
	sig := make([]byte, crypto.SignatureLength)
	rb, sb := r.Bytes(), s.Bytes()
	copy(sig[32-len(rb):32], rb)
	copy(sig[64-len(sb):64], sb)
	if tx.Type() == types.LegacyTxType && tx.Protected() {
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
