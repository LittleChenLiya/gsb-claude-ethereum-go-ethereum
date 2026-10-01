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

package filters

import (
	"context"
	"crypto/ecdsa"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/filtermaps"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/triedb"
)

// loggerABI is the ABI of the Logger test contract.
const loggerABI = `[{"inputs":[],"name":"log0","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint256","name":"t1","type":"uint256"}],"name":"log1","outputs":[],"stateMutability":"nonpayable","type":"function"}]`

// loggerBytecode is the bytecode of the Logger test contract.
var loggerBytecode = common.FromHex("608060405234801561001057600080fd5b50600436106100575760003560e01c80630aa731851461005c5780632a4c08961461006657806378b9a1f314610082578063c670f8641461009e578063c683d6a3146100ba575b600080fd5b6100646100d6565b005b610080600480360381019061007b9190610143565b6100dc565b005b61009c60048036038101906100979190610196565b6100e8565b005b6100b860048036038101906100b391906101d6565b6100f2565b005b6100d460048036038101906100cf9190610203565b6100fa565b005b600080a0565b808284600080a3505050565b8082600080a25050565b80600080a150565b80828486600080a450505050565b600080fd5b6000819050919050565b6101208161010d565b811461012b57600080fd5b50565b60008135905061013d81610117565b92915050565b60008060006060848603121561015c5761015b610108565b5b600061016a8682870161012e565b935050602061017b8682870161012e565b925050604061018c8682870161012e565b9150509250925092565b600080604083850312156101ad576101ac610108565b5b60006101bb8582860161012e565b92505060206101cc8582860161012e565b9150509250929050565b6000602082840312156101ec576101eb610108565b5b60006101fa8482850161012e565b91505092915050565b6000806000806080858703121561021d5761021c610108565b5b600061022b8782880161012e565b945050602061023c8782880161012e565b935050604061024d8782880161012e565b925050606061025e8782880161012e565b9150509295919450925056fea264697066735822122073a4b156f487e59970dc1ef449cc0d51467268f676033a17188edafcee861f9864736f6c63430008110033")

// makeLogTx creates a signed transaction that calls the Logger contract's
// log1 function with the given topic.
func makeLogTx(t *testing.T, signer types.Signer, key *ecdsa.PrivateKey, contract common.Address, topic common.Hash, nonce uint64, gasPrice *big.Int) *types.Transaction {
	t.Helper()
	parsedABI, err := abi.JSON(strings.NewReader(loggerABI))
	if err != nil {
		t.Fatal(err)
	}
	data, err := parsedABI.Pack("log1", topic.Big())
	if err != nil {
		t.Fatal(err)
	}
	tx, err := types.SignTx(types.NewTx(&types.LegacyTx{
		Nonce:    nonce,
		GasPrice: gasPrice,
		Gas:      30000,
		To:       &contract,
		Data:     data,
	}), signer, key)
	if err != nil {
		t.Fatal(err)
	}
	return tx
}

// TestLogFilterSnapshot tests the log filter cursor snapshot functionality.
// It appends blocks, takes a snapshot, appends more blocks, restores the filter
// from the snapshot, and verifies that no logs are duplicated or missed. It
// then simulates a chain reorg and verifies that the filter rewinds to the
// fork point instead of skipping the affected blocks. Finally, it tests that
// an invalid snapshot returns a clear error.
func TestLogFilterSnapshot(t *testing.T) {
	var (
		db           = rawdb.NewMemoryDatabase()
		backend, sys = newTestFilterSystem(db, Config{})
		key1, _      = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		addr1        = crypto.PubkeyToAddress(key1.PublicKey)
		contract     = common.Address{0xfe}
		signer       = types.NewLondonSigner(big.NewInt(1))
		topic1       = common.BytesToHash([]byte("topic1"))
		topic2       = common.BytesToHash([]byte("topic2"))
		topic3       = common.BytesToHash([]byte("topic3"))

		gspec = &core.Genesis{
			Config: params.TestChainConfig,
			Alloc: types.GenesisAlloc{
				addr1:    {Balance: big.NewInt(0).Mul(big.NewInt(100), big.NewInt(params.Ether))},
				contract: {Balance: big.NewInt(0), Code: loggerBytecode},
			},
			BaseFee: big.NewInt(params.InitialBaseFee),
		}
	)

	_, err := gspec.Commit(db, triedb.NewDatabase(db, nil), nil)
	if err != nil {
		t.Fatal(err)
	}

	// Generate chain A (blocks 0-20) with log1 calls at blocks 5 and 15.
	chainA, _ := core.GenerateChain(gspec.Config, gspec.ToBlock(), ethash.NewFaker(), db, 20, func(i int, gen *core.BlockGen) {
		switch i {
		case 5:
			gen.AddTx(makeLogTx(t, signer, key1, contract, topic1, 0, gen.BaseFee()))
		case 15:
			gen.AddTx(makeLogTx(t, signer, key1, contract, topic2, 1, gen.BaseFee()))
		}
	})

	bc, err := core.NewBlockChain(db, gspec, ethash.NewFaker(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bc.InsertChain(chainA); err != nil {
		t.Fatal(err)
	}

	backend.startFilterMaps(0, false, filtermaps.DefaultParams)
	defer backend.stopFilterMaps()

	// updateFmTarget updates the filter maps indexer to the current chain head
	// and waits for it to finish indexing.
	updateFmTarget := func() {
		head := bc.CurrentBlock()
		backend.fm.SetTarget(filtermaps.NewChainView(backend, head.Number.Uint64(), head.Hash()), 0, 0)
		backend.fm.WaitIdle()
	}
	updateFmTarget()

	// Scan [0, latest] and verify the logs.
	filter := sys.NewRangeFilter(0, int64(rpc.LatestBlockNumber), []common.Address{contract}, nil, 0)
	logs, err := filter.Logs(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) != 2 {
		t.Fatalf("expected 2 logs after first scan, got %d", len(logs))
	}
	if logs[0].BlockNumber != 6 || logs[1].BlockNumber != 16 {
		t.Fatalf("unexpected log block numbers: %d, %d", logs[0].BlockNumber, logs[1].BlockNumber)
	}

	// Take a snapshot. The cursor should point to the next block after the
	// scanned range (block 21).
	snap := filter.Snapshot()
	if snap == nil {
		t.Fatal("expected non-nil snapshot")
	}
	if snap.nextBlock != 21 {
		t.Fatalf("expected cursor at block 21, got %d", snap.nextBlock)
	}

	// Generate chain B (blocks 0-25) from genesis with different content
	// (log1 calls at blocks 5, 12, and 22). This will cause a reorg when
	// inserted because chain B is longer (higher total difficulty).
	chainB, _ := core.GenerateChain(gspec.Config, gspec.ToBlock(), ethash.NewFaker(), db, 25, func(i int, gen *core.BlockGen) {
		gen.OffsetTime(1) // make chain B different from chain A
		switch i {
		case 5:
			gen.AddTx(makeLogTx(t, signer, key1, contract, topic1, 0, gen.BaseFee()))
		case 12:
			gen.AddTx(makeLogTx(t, signer, key1, contract, topic3, 1, gen.BaseFee()))
		case 22:
			gen.AddTx(makeLogTx(t, signer, key1, contract, topic2, 2, gen.BaseFee()))
		}
	})

	// Insert chain B, causing a reorg.
	if _, err := bc.InsertChain(chainB); err != nil {
		t.Fatal(err)
	}
	updateFmTarget()

	// Restore the filter from the snapshot. The reorg should be detected and
	// the scan range rewound to the fork point (block 1), so that the affected
	// blocks are re-scanned instead of skipped.
	filter2, err := sys.NewRangeFilterFromSnapshot(snap)
	if err != nil {
		t.Fatalf("unexpected error restoring from snapshot: %v", err)
	}

	// Scan again and verify that no logs are duplicated or missed.
	logs2, err := filter2.Logs(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(logs2) != 3 {
		t.Fatalf("expected 3 logs after reorg restore, got %d", len(logs2))
	}
	expectedBlocks := []uint64{6, 13, 23}
	for i, log := range logs2 {
		if log.BlockNumber != expectedBlocks[i] {
			t.Fatalf("log %d: expected block %d, got %d", i, expectedBlocks[i], log.BlockNumber)
		}
	}

	// Verify the cursor has advanced to the next block after the scanned range.
	snap2 := filter2.Snapshot()
	if snap2.nextBlock != 26 {
		t.Fatalf("expected cursor at block 26 after second scan, got %d", snap2.nextBlock)
	}

	// Test that an invalid snapshot returns a clear error. Create a snapshot
	// with a cursor block hash that is not present in the chain.
	invalidSnap := &LogFilterSnapshot{
		addresses:     []common.Address{contract},
		topics:        nil,
		begin:         0,
		end:           int64(rpc.LatestBlockNumber),
		nextBlock:     21,
		blockHash:     common.HexToHash("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
		resolvedBegin: 0,
	}
	if _, err := sys.NewRangeFilterFromSnapshot(invalidSnap); err == nil {
		t.Fatal("expected error for invalid snapshot, got nil")
	} else {
		t.Logf("invalid snapshot error: %v", err)
	}

	// Test that a nil snapshot returns an error.
	if _, err := sys.NewRangeFilterFromSnapshot(nil); err == nil {
		t.Fatal("expected error for nil snapshot, got nil")
	}
}

// TestLogFilterSnapshotNormal tests the log filter cursor snapshot in the
// normal case where the chain only appends blocks (no reorg). It verifies
// that the cursor advances correctly and that no logs are duplicated or missed
// when the filter is restored from a snapshot and scanned again.
func TestLogFilterSnapshotNormal(t *testing.T) {
	var (
		db           = rawdb.NewMemoryDatabase()
		backend, sys = newTestFilterSystem(db, Config{})
		key1, _      = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		addr1        = crypto.PubkeyToAddress(key1.PublicKey)
		contract     = common.Address{0xfe}
		signer       = types.NewLondonSigner(big.NewInt(1))
		topic1       = common.BytesToHash([]byte("topic1"))
		topic2       = common.BytesToHash([]byte("topic2"))

		gspec = &core.Genesis{
			Config: params.TestChainConfig,
			Alloc: types.GenesisAlloc{
				addr1:    {Balance: big.NewInt(0).Mul(big.NewInt(100), big.NewInt(params.Ether))},
				contract: {Balance: big.NewInt(0), Code: loggerBytecode},
			},
			BaseFee: big.NewInt(params.InitialBaseFee),
		}
	)

	_, err := gspec.Commit(db, triedb.NewDatabase(db, nil), nil)
	if err != nil {
		t.Fatal(err)
	}

	// Generate chain A (blocks 0-10) with log1 calls at blocks 5 and 10.
	chainA, _ := core.GenerateChain(gspec.Config, gspec.ToBlock(), ethash.NewFaker(), db, 10, func(i int, gen *core.BlockGen) {
		switch i {
		case 4:
			gen.AddTx(makeLogTx(t, signer, key1, contract, topic1, 0, gen.BaseFee()))
		case 9:
			gen.AddTx(makeLogTx(t, signer, key1, contract, topic2, 1, gen.BaseFee()))
		}
	})

	bc, err := core.NewBlockChain(db, gspec, ethash.NewFaker(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bc.InsertChain(chainA); err != nil {
		t.Fatal(err)
	}

	backend.startFilterMaps(0, false, filtermaps.DefaultParams)
	defer backend.stopFilterMaps()

	updateFmTarget := func() {
		head := bc.CurrentBlock()
		backend.fm.SetTarget(filtermaps.NewChainView(backend, head.Number.Uint64(), head.Hash()), 0, 0)
		backend.fm.WaitIdle()
	}
	updateFmTarget()

	// Scan [0, latest] and verify the logs.
	filter := sys.NewRangeFilter(0, int64(rpc.LatestBlockNumber), []common.Address{contract}, nil, 0)
	logs, err := filter.Logs(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) != 2 {
		t.Fatalf("expected 2 logs after first scan, got %d", len(logs))
	}

	// Take a snapshot. The cursor should point to block 11.
	snap := filter.Snapshot()
	if snap.nextBlock != 11 {
		t.Fatalf("expected cursor at block 11, got %d", snap.nextBlock)
	}

	// Append chain B (blocks 11-15) with a log1 call at block 13.
	chainB, _ := core.GenerateChain(gspec.Config, chainA[len(chainA)-1], ethash.NewFaker(), db, 5, func(i int, gen *core.BlockGen) {
		if i == 2 {
			gen.AddTx(makeLogTx(t, signer, key1, contract, topic1, 2, gen.BaseFee()))
		}
	})
	if _, err := bc.InsertChain(chainB); err != nil {
		t.Fatal(err)
	}
	updateFmTarget()

	// Restore from snapshot and scan again. No reorg should be detected, so
	// the filter should resume from block 11.
	filter2, err := sys.NewRangeFilterFromSnapshot(snap)
	if err != nil {
		t.Fatalf("unexpected error restoring from snapshot: %v", err)
	}
	logs2, err := filter2.Logs(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(logs2) != 1 {
		t.Fatalf("expected 1 log after second scan, got %d", len(logs2))
	}
	if logs2[0].BlockNumber != 13 {
		t.Fatalf("expected log at block 13, got %d", logs2[0].BlockNumber)
	}

	// Verify the cursor has advanced to block 16.
	snap2 := filter2.Snapshot()
	if snap2.nextBlock != 16 {
		t.Fatalf("expected cursor at block 16, got %d", snap2.nextBlock)
	}

	// Verify that scanning the full range again returns all 3 logs (no
	// duplicates or misses).
	filter3 := sys.NewRangeFilter(0, int64(rpc.LatestBlockNumber), []common.Address{contract}, nil, 0)
	logs3, err := filter3.Logs(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(logs3) != 3 {
		t.Fatalf("expected 3 logs after full re-scan, got %d", len(logs3))
	}
}

// TestLogFilterSnapshotBeforeScan tests that a snapshot taken before any scan
// is performed returns a fresh filter with the original range.
func TestLogFilterSnapshotBeforeScan(t *testing.T) {
	var (
		db           = rawdb.NewMemoryDatabase()
		_, sys = newTestFilterSystem(db, Config{})
	)

	// Create a filter without scanning.
	filter := sys.NewRangeFilter(0, 100, nil, nil, 0)
	snap := filter.Snapshot()
	if snap.nextBlock != 0 {
		t.Fatalf("expected cursor at 0 before scan, got %d", snap.nextBlock)
	}

	// Restore from the snapshot. Should create a fresh filter.
	filter2, err := sys.NewRangeFilterFromSnapshot(snap)
	if err != nil {
		t.Fatalf("unexpected error restoring from snapshot: %v", err)
	}
	if filter2.begin != 0 || filter2.end != 100 {
		t.Fatalf("expected fresh filter with range [0, 100], got [%d, %d]", filter2.begin, filter2.end)
	}
}
