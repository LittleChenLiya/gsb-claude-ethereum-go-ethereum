// Copyright 2025 The go-ethereum Authors
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

package legacypool

import (
	"crypto/ecdsa"
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

// setupReportPool creates a pool with small capacity limits for deterministic
// replacement-report testing, and funds the test account.
func setupReportPool(t *testing.T, globalSlots, globalQueue uint64) (*LegacyPool, *ecdsa.PrivateKey) {
	t.Helper()
	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	blockchain := newTestBlockChain(eip1559Config, 10000000, statedb, new(event.Feed))
	key, _ := crypto.GenerateKey()
	config := testTxPoolConfig
	config.GlobalSlots = globalSlots
	config.GlobalQueue = globalQueue
	pool := New(config, blockchain)
	if err := pool.Init(config.PriceLimit, blockchain.CurrentBlock(), newReserver()); err != nil {
		t.Fatal(err)
	}
	<-pool.initDoneCh
	// Fund the account generously so balance never interferes with the report.
	addr := crypto.PubkeyToAddress(key.PublicKey)
	pool.mu.Lock()
	pool.currentState.AddBalance(addr, uint256.MustFromBig(new(big.Int).Mul(big.NewInt(100), big.NewInt(params.Ether))), tracing.BalanceChangeUnspecified)
	pool.mu.Unlock()
	return pool, key
}

// TestReportReplacement verifies the read-only replacement reason report across
// the three admission constraints: sufficient price bump, insufficient price
// bump, and capacity pressure. For each case the report is compared against the
// real admission result, and the pool state is verified unchanged after the
// report.
func TestReportReplacement(t *testing.T) {
	t.Parallel()

	var (
		gwei    = big.NewInt(params.GWei)
		price   = new(big.Int).Mul(gwei, big.NewInt(10))               // 10 gwei incumbent
		bumpOK  = new(big.Int).Mul(gwei, big.NewInt(12))               // 12 gwei, 20% bump (>= 10%)
		bumpBad = new(big.Int).Add(price, new(big.Int).Div(gwei, big.NewInt(2))) // 10.5 gwei, 5% bump (< 10%)
		cheap   = gwei                                                 // 1 gwei, underpriced
	)

	tests := []struct {
		name       string
		setup      func(t *testing.T, pool *LegacyPool, key *ecdsa.PrivateKey) *types.Transaction
		wantReason txpool.ReplaceReason
		wantErr    error
	}{
		{
			name: "sufficient price bump accepted",
			setup: func(t *testing.T, pool *LegacyPool, key *ecdsa.PrivateKey) *types.Transaction {
				old := dynamicFeeTx(0, 21000, price, price, key)
				if err := pool.addRemoteSync(old); err != nil {
					t.Fatalf("failed to add old tx: %v", err)
				}
				return dynamicFeeTx(0, 21000, bumpOK, bumpOK, key)
			},
			wantReason: txpool.ReplaceAccepted,
			wantErr:    nil,
		},
		{
			name: "insufficient price bump rejected",
			setup: func(t *testing.T, pool *LegacyPool, key *ecdsa.PrivateKey) *types.Transaction {
				old := dynamicFeeTx(0, 21000, price, price, key)
				if err := pool.addRemoteSync(old); err != nil {
					t.Fatalf("failed to add old tx: %v", err)
				}
				return dynamicFeeTx(0, 21000, bumpBad, bumpBad, key)
			},
			wantReason: txpool.ReplaceReasonPrice,
			wantErr:    txpool.ErrReplaceUnderpriced,
		},
		{
			name: "capacity pressure rejects before price",
			setup: func(t *testing.T, pool *LegacyPool, key *ecdsa.PrivateKey) *types.Transaction {
				// Fill the pool with high-priced pending txs from the same
				// account. The nonce-0 tx is the incumbent the candidate would
				// replace.
				for i := uint64(0); i < 4; i++ {
					tx := dynamicFeeTx(i, 21000, price, price, key)
					if err := pool.addRemoteSync(tx); err != nil {
						t.Fatalf("failed to fill pool: %v", err)
					}
				}
				// Candidate is underpriced relative to the pooled txs and also
				// fails the price bump; capacity must reject first.
				return dynamicFeeTx(0, 21000, cheap, cheap, key)
			},
			wantReason: txpool.ReplaceReasonCapacity,
			wantErr:    txpool.ErrUnderpriced,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// GlobalSlots=3, GlobalQueue=1 => capacity threshold = 4 slots.
			// Filling with 4 txs makes the pool full; the 1-slot candidate
			// then triggers the capacity check.
			pool, key := setupReportPool(t, 3, 1)
			defer pool.Close()

			newTx := tt.setup(t, pool, key)

			// Capture pool state before the report to verify read-only behavior.
			pendingBefore, queuedBefore := pool.Stats()
			allBefore := pool.all.Count()

			// Report the replacement (read-only).
			report := pool.ReportReplacement(newTx)

			// Verify the report reason and error.
			if report.Reason != tt.wantReason {
				t.Errorf("report reason = %s, want %s", report.Reason, tt.wantReason)
			}
			if !errors.Is(report.Err, tt.wantErr) {
				t.Errorf("report err = %v, want %v", report.Err, tt.wantErr)
			}

			// Verify the pool state is unchanged after the report.
			pendingAfter, queuedAfter := pool.Stats()
			allAfter := pool.all.Count()
			if pendingBefore != pendingAfter || queuedBefore != queuedAfter || allBefore != allAfter {
				t.Errorf("pool state changed after report: pending %d->%d, queued %d->%d, all %d->%d",
					pendingBefore, pendingAfter, queuedBefore, queuedAfter, allBefore, allAfter)
			}

			// Actually attempt the replacement and compare with the report.
			err := pool.addRemoteSync(newTx)
			if tt.wantErr == nil {
				if err != nil {
					t.Errorf("actual add err = %v, want nil (report said accepted)", err)
				}
			} else {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("actual add err = %v, want %v (report said %s)", err, tt.wantErr, tt.wantErr)
				}
			}
		})
	}
}

// TestReportReplacementAggregator verifies that the TxPool aggregator exposes
// the replacement report and delegates to the subpool handling the tx type.
func TestReportReplacementAggregator(t *testing.T) {
	t.Parallel()

	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	blockchain := newTestBlockChain(eip1559Config, 10000000, statedb, new(event.Feed))
	key, _ := crypto.GenerateKey()

	config := testTxPoolConfig
	config.GlobalSlots = 4
	config.GlobalQueue = 1
	legacyPool := New(config, blockchain)

	pool, err := txpool.New(config.PriceLimit, blockchain, []txpool.SubPool{legacyPool})
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	// Fund the account.
	addr := crypto.PubkeyToAddress(key.PublicKey)
	statedb.AddBalance(addr, uint256.MustFromBig(new(big.Int).Mul(big.NewInt(100), big.NewInt(params.Ether))), tracing.BalanceChangeUnspecified)

	var (
		gwei   = big.NewInt(params.GWei)
		price  = new(big.Int).Mul(gwei, big.NewInt(10))
		bumpOK = new(big.Int).Mul(gwei, big.NewInt(12))
	)

	// Add the old tx through the aggregator.
	oldTx := dynamicFeeTx(0, 21000, price, price, key)
	if errs := pool.Add([]*types.Transaction{oldTx}, true); errs[0] != nil {
		t.Fatalf("failed to add old tx: %v", errs[0])
	}

	// Report a sufficient-bump replacement through the aggregator.
	newTx := dynamicFeeTx(0, 21000, bumpOK, bumpOK, key)
	report := pool.ReportReplacement(newTx)
	if report.Reason != txpool.ReplaceAccepted {
		t.Errorf("report reason = %s, want accepted", report.Reason)
	}
	if report.Err != nil {
		t.Errorf("report err = %v, want nil", report.Err)
	}

	// Verify the report matches actual acceptance.
	if errs := pool.Add([]*types.Transaction{newTx}, true); errs[0] != nil {
		t.Errorf("actual add err = %v, want nil", errs[0])
	}
}
