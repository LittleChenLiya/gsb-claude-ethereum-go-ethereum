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

package legacypool

import (
	"crypto/ecdsa"
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/params"
)

// setupSmallPool creates a legacy pool backed by a tiny capacity so that
// capacity pressure can be reproduced deterministically with a handful of
// transactions: 16 global pending slots and 1 queued slot (17 slots total).
func setupSmallPool() (*LegacyPool, *ecdsa.PrivateKey, *ecdsa.PrivateKey) {
	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	blockchain := newTestBlockChain(params.TestChainConfig, 10000000, statedb, new(event.Feed))

	config := testTxPoolConfig
	config.NoLocals = true
	config.AccountSlots = 64
	config.GlobalSlots = 16
	config.AccountQueue = 1
	config.GlobalQueue = 1

	key, _ := crypto.GenerateKey()
	fillerKey, _ := crypto.GenerateKey()

	pool := New(config, blockchain)
	if err := pool.Init(config.PriceLimit, blockchain.CurrentBlock(), newReserver()); err != nil {
		panic(err)
	}
	<-pool.initDoneCh
	return pool, key, fillerKey
}

// poolContents returns the hashes of every tracked transaction, allowing test
// code to prove that a read-only replacement probe did not modify pool state.
func poolContents(pool *LegacyPool) map[common.Hash]struct{} {
	have := make(map[common.Hash]struct{})
	pool.all.Range(func(hash common.Hash, _ *types.Transaction) bool {
		have[hash] = struct{}{}
		return true
	})
	return have
}

// TestCheckReplacement drives the read-only replacement reason report with
// old/new transaction pairs and compares its prediction with the real result of
// inserting the new transaction. It covers:
//   - a replacement with an adequate price bump (accepted),
//   - a replacement with an inadequate price bump (price rejects first),
//   - a stale-nonce candidate (nonce rejects first),
//   - capacity pressure where the pool is full and the candidate cannot evict
//     anything (capacity rejects before the replacement price-bump check),
//   - capacity pressure where the candidate is expensive enough to evict and is
//     therefore still accepted,
//   - the reorg throttling path while the pool is full (capacity rejects first).
func TestCheckReplacement(t *testing.T) {
	const (
		fillerPrice = int64(120) // gas price of the capacity-filling transactions
		gas         = uint64(100000)
	)

	type want struct {
		accepted bool
		reason   txpool.ReplacementRejectReason
		err      error // sentinel matched with errors.Is; nil when accepted
	}

	type scenario struct {
		name     string
		fill     bool  // fill the pool to capacity before probing
		throttle bool  // exhaust the between-reorg replacement budget
		seedOld  bool  // seed the old transaction (nonce 0) signed by key
		oldPrice int64 // gas price of the seeded old transaction
		setNonce uint64
		hasNonce bool
		newPrice int64
		newGas   uint64 // gas limit of the candidate (defaults to gas)
		want     want
	}
	cases := []scenario{
		{
			name:     "adequate bump",
			seedOld:  true,
			oldPrice: 100,
			newPrice: 110, // exactly oldPrice*(100+10)/100
			want:     want{accepted: true},
		},
		{
			name:     "inadequate bump",
			seedOld:  true,
			oldPrice: 100,
			newPrice: 105, // above the old price but below the 10% threshold
			want:     want{accepted: false, reason: txpool.ReplacementRejectedPrice, err: txpool.ErrReplaceUnderpriced},
		},
		{
			name:     "stale nonce",
			seedOld:  false,
			newPrice: 110,
			setNonce: 1,
			hasNonce: true,
			want:     want{accepted: false, reason: txpool.ReplacementRejectedNonce, err: core.ErrNonceTooLow},
		},
		{
			// The candidate carries no price bump over its own old tx, but the
			// pool is full with transactions at the very same price. The global
			// capacity/underpriced gate rejects it (it cannot evict anything)
			// before the replacement price-bump rule is even reached. This proves
			// capacity is evaluated before the replacement price bump.
			name:     "capacity pressure underpriced before price bump",
			seedOld:  true,
			fill:     true,
			oldPrice: fillerPrice,
			newPrice: fillerPrice, // equal: not better than the cheapest pooled tx
			newGas:   gas + 1,     // differ from the old tx so it is a distinct replacement
			want:     want{accepted: false, reason: txpool.ReplacementRejectedCapacity, err: txpool.ErrUnderpriced},
		},
		{
			name:     "capacity pressure accepted after eviction",
			seedOld:  true,
			fill:     true,
			oldPrice: 100,
			newPrice: 2000, // expensive enough to evict the cheapest pooled tx
			want:     want{accepted: true},
		},
		{
			name:     "capacity pressure reorg throttle",
			seedOld:  true,
			fill:     true,
			throttle: true,
			oldPrice: 100,
			newPrice: 2000,
			want:     want{accepted: false, reason: txpool.ReplacementRejectedCapacity, err: ErrTxPoolOverflow},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pool, key, fillerKey := setupSmallPool()
			defer pool.Close()

			from := crypto.PubkeyToAddress(key.PublicKey)
			filler := crypto.PubkeyToAddress(fillerKey.PublicKey)

			testAddBalance(pool, from, big.NewInt(1000000000000000000))
			testAddBalance(pool, filler, big.NewInt(1000000000000000000))
			if tc.hasNonce {
				testSetNonce(pool, from, tc.setNonce)
			}

			// Establish the already pooled "old" transaction and, when requested,
			// fill every remaining slot with expensive filler transactions.
			if tc.seedOld {
				oldTx := pricedTransaction(0, gas, big.NewInt(tc.oldPrice), key)
				if err := pool.addRemoteSync(oldTx); err != nil {
					t.Fatalf("failed to seed old transaction: %v", err)
				}
			}
			if tc.fill {
				// Together with the old tx these fill the 16 pending slots plus
				// the single queue slot (17 slots total).
				for nonce := uint64(0); nonce < 16; nonce++ {
					tx := pricedTransaction(nonce, gas, big.NewInt(fillerPrice), fillerKey)
					if err := pool.addRemoteSync(tx); err != nil {
						t.Fatalf("failed to add filler %d: %v", nonce, err)
					}
				}
			}
			if tc.throttle {
				pool.mu.Lock()
				pool.changesSinceReorg = int(pool.config.GlobalSlots)
				pool.mu.Unlock()
			}

			// Candidate transaction that attempts to replace (or take) nonce 0.
			candidateGas := tc.newGas
			if candidateGas == 0 {
				candidateGas = gas
			}
			candidate := pricedTransaction(0, candidateGas, big.NewInt(tc.newPrice), key)

			// Snapshot pool state to prove the probe is strictly read-only.
			before := poolContents(pool)
			beforeSlots := pool.all.Slots()
			beforePriced := pool.priced.urgent.Len() + pool.priced.floating.Len()

			report, probeErr := pool.CheckReplacement(candidate)

			after := poolContents(pool)
			afterSlots := pool.all.Slots()
			afterPriced := pool.priced.urgent.Len() + pool.priced.floating.Len()

			if probeErr != nil {
				t.Fatalf("unexpected probe error: %v", probeErr)
			}
			if len(before) != len(after) {
				t.Fatalf("probe changed tracked tx count: before %d, after %d", len(before), len(after))
			}
			for hash := range before {
				if _, ok := after[hash]; !ok {
					t.Fatalf("probe removed pooled transaction %s", hash)
				}
			}
			if beforeSlots != afterSlots {
				t.Fatalf("probe changed slot count: before %d, after %d", beforeSlots, afterSlots)
			}
			if beforePriced != afterPriced {
				t.Fatalf("probe changed priced heap size: before %d, after %d", beforePriced, afterPriced)
			}
			if pool.all.Get(candidate.Hash()) != nil {
				t.Fatalf("probe inserted the candidate into the pool")
			}

			if report.Accepted != tc.want.accepted {
				t.Fatalf("accepted mismatch: report %v, want %v (err in report: %v)", report.Accepted, tc.want.accepted, report.Err)
			}
			if !tc.want.accepted {
				if report.Reason != tc.want.reason {
					t.Fatalf("reason mismatch: report %q, want %q", report.Reason, tc.want.reason)
				}
				if report.Err == nil || !errors.Is(report.Err, tc.want.err) {
					t.Fatalf("error mismatch: report %v, want wraps %v", report.Err, tc.want.err)
				}
			}

			// Compare the prediction with what a real insertion actually does.
			realErr := pool.addRemoteSync(candidate)
			if tc.want.accepted {
				if realErr != nil {
					t.Fatalf("report predicted acceptance but real insertion rejected: %v", realErr)
				}
				if pool.all.Get(candidate.Hash()) == nil {
					t.Fatalf("accepted candidate missing from pool after real insertion")
				}
			} else {
				if realErr == nil {
					t.Fatalf("report predicted rejection (%q) but real insertion succeeded", tc.want.err)
				}
				if !errors.Is(realErr, tc.want.err) {
					t.Fatalf("real insertion error mismatch: got %v, want wraps %v", realErr, tc.want.err)
				}
				if pool.all.Get(candidate.Hash()) != nil {
					t.Fatalf("rejected candidate must not be tracked by the pool")
				}
			}
		})
	}
}

// TestValidateReplacementPrice checks the pure price-bump predicate used by the
// report, including the Wei-level edge cases where a strictly higher price is
// not enough and the percentage threshold still rejects.
func TestValidateReplacementPrice(t *testing.T) {
	mk := func(price int64) *types.Transaction {
		key, _ := crypto.GenerateKey()
		return pricedTransaction(0, 100000, big.NewInt(price), key)
	}
	cases := []struct {
		name      string
		oldPrice  int64
		newPrice  int64
		wantError bool
	}{
		{"equal prices rejected", 100, 100, true},
		{"lower price rejected", 100, 99, true},
		{"tiny bump below threshold rejected", 100, 101, true},
		{"bump exactly at threshold accepted", 100, 110, false},
		{"bump above threshold accepted", 100, 111, false},
		{"one wei old needs one wei bump", 1, 2, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := txpool.ValidateReplacementPrice(mk(tc.oldPrice), mk(tc.newPrice), 10)
			if tc.wantError && !errors.Is(err, txpool.ErrReplaceUnderpriced) {
				t.Fatalf("got %v, want ErrReplaceUnderpriced", err)
			}
			if !tc.wantError && err != nil {
				t.Fatalf("got %v, want nil", err)
			}
		})
	}
}

// TestCheckReplacementAlreadyKnown ensures probing an already pooled
// transaction reports ErrAlreadyKnown, exactly like the real insertion path,
// and leaves the pool untouched.
func TestCheckReplacementAlreadyKnown(t *testing.T) {
	pool, key, _ := setupSmallPool()
	defer pool.Close()

	from := crypto.PubkeyToAddress(key.PublicKey)
	testAddBalance(pool, from, big.NewInt(1000000000000000000))

	tx := pricedTransaction(0, 100000, big.NewInt(100), key)
	if err := pool.addRemoteSync(tx); err != nil {
		t.Fatalf("failed to seed transaction: %v", err)
	}
	count := pool.all.Count()

	report, err := pool.CheckReplacement(tx)
	if !errors.Is(err, txpool.ErrAlreadyKnown) {
		t.Fatalf("got report %v / err %v, want ErrAlreadyKnown", report, err)
	}
	if pool.all.Count() != count {
		t.Fatalf("probe changed pool size: before %d, after %d", count, pool.all.Count())
	}
}
