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
	stdcrypto "crypto/ecdsa"
	"errors"
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
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/triedb"
)

// cursorTestABI/cursorTestBytecodeHex describe a tiny contract whose only
// method log1(uint256 t1) emits log1 with t1 as the single topic. The
// bytecode is the proven "Logger" artifact also used by filter_test.go.
var cursorTestABI = mustParseCursorABI()

const cursorTestBytecodeHex = "608060405234801561001057600080fd5b50600436106100575760003560e01c80630aa731851461005c5780632a4c08961461006657806378b9a1f314610082578063c670f8641461009e578063c683d6a3146100ba575b600080fd5b6100646100d6565b005b610080600480360381019061007b9190610143565b6100dc565b005b61009c60048036038101906100979190610196565b6100e8565b005b6100b860048036038101906100b391906101d6565b6100f2565b005b6100d460048036038101906100cf9190610203565b6100fa565b005b600080a0565b808284600080a3505050565b8082600080a25050565b80600080a150565b80828486600080a450505050565b600080fd5b6000819050919050565b6101208161010d565b811461012b57600080fd5b50565b60008135905061013d81610117565b92915050565b60008060006060848603121561015c5761015b610108565b5b600061016a8682870161012e565b935050602061017b8682870161012e565b925050604061018c8682870161012e565b9150509250925092565b600080604083850312156101ad576101ac610108565b5b60006101bb8582860161012e565b92505060206101cc8582860161012e565b9150509250929050565b6000602082840312156101ec576101eb610108565b5b60006101fa8482850161012e565b91505092915050565b6000806000806080858703121561021d5761021c610108565b5b600061022b8782880161012e565b945050602061023c8782880161012e565b935050604061024d8782880161012e565b925050606061025e8782880161012e565b9150509295919450925056fea264697066735822122073a4b156f487e59970dc1ef449cc0d51467268f676033a17188edafcee861f9864736f6c63430008110033"

func mustParseCursorABI() abi.ABI {
	abiStr := `[{"inputs":[{"internalType":"uint256","name":"t1","type":"uint256"}],"name":"log1","outputs":[],"stateMutability":"nonpayable","type":"function"}]`
	parsed, err := abi.JSON(strings.NewReader(abiStr))
	if err != nil {
		panic(err)
	}
	return parsed
}

// cursorTestEnv holds an in-memory chain with a log-emitting contract and a
// filter system on top of it.
type cursorTestEnv struct {
	t        *testing.T
	db       ethdb.Database
	bc       *core.BlockChain
	backend  *testBackend
	sys      *FilterSystem
	indexed  bool
	privKey  *stdcrypto.PrivateKey
	addr     common.Address
	contract common.Address
	signer   types.Signer
}

// newCursorTestEnv builds the genesis state and a blockchain. The filter maps
// indexer is started lazily via startIndexer after at least one block has been
// imported, as the test backend is not wired to chain events and an indexer
// without a target cannot answer WaitIdle (same pattern as TestRangeLogs).
func newCursorTestEnv(t *testing.T, indexed bool) (*cursorTestEnv, func()) {
	t.Helper()
	var (
		db           = rawdb.NewMemoryDatabase()
		backend, sys = newTestFilterSystem(db, Config{})
		key, _       = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		addr         = crypto.PubkeyToAddress(key.PublicKey)
		contract     = common.Address{0xfe}
		gspec        = &core.Genesis{
			Config: params.TestChainConfig,
			Alloc: types.GenesisAlloc{
				addr:     {Balance: big.NewInt(0).Mul(big.NewInt(1000), big.NewInt(params.Ether))},
				contract: {Balance: new(big.Int), Code: common.FromHex(cursorTestBytecodeHex)},
			},
			BaseFee: big.NewInt(params.InitialBaseFee),
		}
	)
	if _, err := gspec.Commit(db, triedb.NewDatabase(db, nil), nil); err != nil {
		t.Fatal(err)
	}
	options := core.DefaultConfig().WithStateScheme(rawdb.HashScheme)
	options.TxLookupLimit = 0
	bc, err := core.NewBlockChain(db, gspec, ethash.NewFaker(), options)
	if err != nil {
		t.Fatal(err)
	}
	env := &cursorTestEnv{
		t:        t,
		db:       db,
		bc:       bc,
		backend:  backend,
		sys:      sys,
		indexed:  indexed,
		privKey:  key,
		addr:     addr,
		contract: contract,
		signer:   types.NewLondonSigner(big.NewInt(1)),
	}
	teardown := func() {
		if env.backend.fm != nil {
			env.backend.stopFilterMaps()
		}
		bc.Stop()
		db.Close()
	}
	return env, teardown
}

// startIndexer starts the test filter maps indexer and points it at the
// current head.
func (env *cursorTestEnv) startIndexer() {
	env.backend.startFilterMaps(0, !env.indexed, filtermaps.DefaultParams)
	env.syncIndexer()
}

// logTx builds a transaction that emits a log whose single topic encodes the
// given value. Nonces are managed by the caller (they must stay in chain
// order across generated segments).
func (env *cursorTestEnv) logTx(value, nonce uint64, baseFee *big.Int) *types.Transaction {
	data, err := cursorTestABI.Pack("log1", new(big.Int).SetUint64(value))
	if err != nil {
		env.t.Fatal(err)
	}
	tx, err := types.SignNewTx(env.privKey, env.signer, &types.LegacyTx{
		Nonce:    nonce,
		GasPrice: baseFee,
		Gas:      300000,
		To:       &env.contract,
		Data:     data,
	})
	if err != nil {
		env.t.Fatal(err)
	}
	return tx
}

// generateBlocks mines n blocks on top of parent; every block contains one
// log-emitting transaction. topicFor maps the new block number to the emitted
// log topic and nonceFor maps it to the sender nonce. The blocks are returned
// without being inserted.
//
// Distinct topic/nonce functions are used for the main and the side chain so
// that blocks at the same height carry different transactions and logs.
func (env *cursorTestEnv) generateBlocks(parent *types.Block, n int, topicFor, nonceFor func(number uint64) uint64) []*types.Block {
	blocks, _ := core.GenerateChain(params.TestChainConfig, parent, ethash.NewFaker(), env.db, n, func(i int, gen *core.BlockGen) {
		blockNumber := parent.NumberU64() + uint64(i) + 1
		gen.AddTx(env.logTx(topicFor(blockNumber), nonceFor(blockNumber), gen.BaseFee()))
	})
	return blocks
}

// mainTopic/mainNonce assign topic==blockNumber and sequential nonces for the
// canonical chain.
func mainTopic(number uint64) uint64 { return number }
func mainNonce(number uint64) uint64 { return number - 1 }

// sideTopic assigns a disjoint topic range to the side chain blocks.
func sideTopic(number uint64) uint64 { return 1_000_000 + number }

// insert imports the blocks as the new canonical chain segment and points the
// (test) filter maps indexer at the new head, waiting until it catches up.
// Before the indexer has been started it only imports the blocks.
func (env *cursorTestEnv) insert(blocks []*types.Block) {
	if _, err := env.bc.InsertChain(blocks); err != nil {
		env.t.Fatal(err)
	}
	if env.backend.fm != nil {
		env.syncIndexer()
	}
}

// syncIndexer advances the test backend's filter maps target to the current
// chain head. The test backend is not wired to chain events, so the indexer
// has to be pointed at new blocks explicitly (same pattern as TestRangeLogs).
func (env *cursorTestEnv) syncIndexer() {
	head := env.bc.CurrentBlock()
	env.backend.fm.SetTarget(filtermaps.NewChainView(env.backend, head.Number.Uint64(), head.Hash()), 0, 0)
	env.backend.fm.WaitIdle()
}

// blockTopic is the topic used by the log emitted in the given block number.
func blockTopic(number uint64) common.Hash {
	return common.BigToHash(new(big.Int).SetUint64(number))
}

// expectedLogs returns one matching log per canonical block in [from, to]
// using topicFor(blockNumber) as the expected first topic.
func (env *cursorTestEnv) expectedLogs(from, to uint64, topicFor func(uint64) uint64) []*types.Log {
	var logs []*types.Log
	for n := from; n <= to; n++ {
		logs = append(logs, &types.Log{
			Address:     env.contract,
			Topics:      []common.Hash{common.BigToHash(new(big.Int).SetUint64(topicFor(n)))},
			BlockNumber: n,
			BlockHash:   env.bc.GetCanonicalHash(n),
		})
	}
	return logs
}

// assertLogs compares the address/topic/block number/block hash of got and
// want logs and also fails on duplicate deliveries.
func (env *cursorTestEnv) assertLogs(stage string, got, want []*types.Log) {
	env.t.Helper()
	if len(got) != len(want) {
		env.t.Fatalf("%s: expected %d logs, got %d (%s)", stage, len(want), len(got), describeLogs(got))
	}
	seen := make(map[[2]common.Hash]struct{}, len(got))
	for i, g := range got {
		w := want[i]
		if g.Address != w.Address || g.BlockNumber != w.BlockNumber || g.BlockHash != w.BlockHash ||
			len(g.Topics) != 1 || g.Topics[0] != w.Topics[0] {
			env.t.Fatalf("%s: log %d mismatch:\n got  block=%d hash=%s topics=%v addr=%s\n want block=%d hash=%s topics=%v addr=%s",
				stage, i, g.BlockNumber, g.BlockHash.TerminalString(), g.Topics, g.Address,
				w.BlockNumber, w.BlockHash.TerminalString(), w.Topics, w.Address)
		}
		key := [2]common.Hash{g.BlockHash, g.Topics[0]}
		if _, ok := seen[key]; ok {
			env.t.Fatalf("%s: duplicate delivery of block %d log", stage, g.BlockNumber)
		}
		seen[key] = struct{}{}
	}
}

func describeLogs(logs []*types.Log) string {
	var b strings.Builder
	for i, l := range logs {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString("block=")
		b.WriteString(new(big.Int).SetUint64(l.BlockNumber).String())
	}
	return b.String()
}

// newCursorFilter creates a fresh range filter scanning [begin, latest] with
// cursor tracking initialized to the given snapshot.
func (env *cursorTestEnv) newCursorFilter(begin int64, cursor CursorSnapshot) *Filter {
	return env.sys.NewRangeFilterWithCursor(begin, rpc.LatestBlockNumber.Int64(),
		[]common.Address{env.contract}, [][]common.Hash{nil}, 0, cursor)
}

// runCursorScenario exercises cursor snapshots over block appends and a chain
// reorg, rebuilding the filter from the snapshot between every step. It is
// executed in both indexed and unindexed modes.
func runCursorScenario(t *testing.T, indexed bool) {
	env, teardown := newCursorTestEnv(t, indexed)
	defer teardown()

	const (
		mainN   = 8 // initial main chain: blocks 1..8
		appendN = 1 // one more main chain block appended before the reorg
		forkAt  = 5 // side chain forks after block 5 (blocks 1..5 are shared)
		sideN   = 5 // side chain has blocks 6..10 (longer than old 6..9)
	)
	genesis := env.bc.Genesis()

	// Phase 1: append blocks 1..8 and scan them with a fresh filter.
	env.insert(env.generateBlocks(genesis, mainN, mainTopic, mainNonce))
	if env.bc.CurrentBlock().Number.Uint64() != mainN {
		t.Fatal("unexpected head after main chain insert")
	}
	// Start the (test) filter maps indexer after the first import.
	env.startIndexer()

	f := env.newCursorFilter(0, CursorSnapshot{})
	logs, err := f.Logs(context.Background())
	if err != nil {
		t.Fatal("initial scan failed:", err)
	}
	env.assertLogs("initial scan", logs, env.expectedLogs(1, mainN, mainTopic))
	cursor, err := f.Cursor()
	if err != nil {
		t.Fatal(err)
	}
	if cursor.NextBlock != mainN+1 || cursor.LastBlockHash != env.bc.GetCanonicalHash(mainN) {
		t.Fatalf("initial cursor mismatch: %+v", cursor)
	}

	// Phase 2: append one more block, rebuild the filter from the snapshot.
	env.insert(env.generateBlocks(env.bc.GetBlockByNumber(mainN), appendN, mainTopic, mainNonce))
	f = env.newCursorFilter(0, cursor)
	logs, err = f.Logs(context.Background())
	if err != nil {
		t.Fatal("resume scan failed:", err)
	}
	env.assertLogs("resume after append", logs, env.expectedLogs(mainN+1, mainN+uint64(appendN), mainTopic))
	cursor, _ = f.Cursor()
	oldHead := uint64(mainN + appendN)
	if cursor.NextBlock != oldHead+1 || cursor.LastBlockHash != env.bc.GetCanonicalHash(oldHead) {
		t.Fatalf("resumed cursor mismatch: %+v", cursor)
	}
	// Polling again with no new blocks returns an empty list without error
	// and without moving the cursor.
	f = env.newCursorFilter(0, cursor)
	logs, err = f.Logs(context.Background())
	if err != nil || len(logs) != 0 {
		t.Fatalf("caught-up poll expected empty logs, got err=%v len=%d", err, len(logs))
	}
	cursor2, _ := f.Cursor()
	if cursor2 != cursor {
		t.Fatalf("caught-up poll moved the cursor: %+v vs %+v", cursor2, cursor)
	}

	// Phase 3: reorg at block 5; side chain 6..10 replaces old blocks 6..9.
	// Side chain blocks reuse the sender nonces valid after block 5 but emit
	// different topics, so they carry distinct transactions and logs.
	forkParent := env.bc.GetBlockByNumber(forkAt)
	side := env.generateBlocks(forkParent, sideN, sideTopic, mainNonce)
	env.insert(side)
	newHead := forkAt + uint64(sideN)
	if head := env.bc.CurrentBlock().Number.Uint64(); head != newHead {
		t.Fatalf("unexpected head after reorg: %d", head)
	}

	// Rebuild the filter with the pre-reorg cursor: it must roll back to the
	// first block after the common ancestor (block 6) and deliver the side
	// chain logs without skipping blocks.
	f = env.newCursorFilter(0, cursor)
	logs, err = f.Logs(context.Background())
	if err != nil {
		t.Fatal("resume after reorg failed:", err)
	}
	env.assertLogs("resume after reorg", logs, env.expectedLogs(forkAt+1, newHead, sideTopic))
	cursor, _ = f.Cursor()
	if cursor.NextBlock != newHead+1 || cursor.LastBlockHash != env.bc.GetCanonicalHash(newHead) {
		t.Fatalf("post-reorg cursor mismatch: %+v", cursor)
	}

	// Phase 4: no duplicates / no gaps over the whole lifecycle. The shared
	// prefix 1..5 was delivered by the initial scans and is still canonical;
	// combining it with the post-reorg delivery must cover the final chain.
	// finalTopic maps a block number of the final canonical chain to its topic.
	finalTopic := func(number uint64) uint64 {
		if number <= forkAt {
			return mainTopic(number)
		}
		return sideTopic(number)
	}
	finalDelivery := append(env.expectedLogs(1, forkAt, mainTopic), logs...)
	env.assertLogs("no duplicates/no gaps over final chain", finalDelivery, env.expectedLogs(1, newHead, finalTopic))

	// A full rescan of the final chain must return the same canonical set.
	f = env.newCursorFilter(0, CursorSnapshot{})
	logs, err = f.Logs(context.Background())
	if err != nil {
		t.Fatal("full rescan failed:", err)
	}
	env.assertLogs("full rescan of final chain", logs, env.expectedLogs(1, newHead, finalTopic))

	// Running the whole scenario a second time with fresh filters on the same
	// chain state must give identical results (repeatability check).
	f = env.newCursorFilter(0, CursorSnapshot{})
	logs, err = f.Logs(context.Background())
	if err != nil {
		t.Fatal("repeat full rescan failed:", err)
	}
	env.assertLogs("repeated full rescan", logs, env.expectedLogs(1, newHead, finalTopic))
	cursor, _ = f.Cursor()
	f = env.newCursorFilter(0, cursor)
	logs, err = f.Logs(context.Background())
	if err != nil || len(logs) != 0 {
		t.Fatalf("repeated caught-up poll expected empty logs, got err=%v len=%d", err, len(logs))
	}

	// Phase 5: invalid snapshots must be reported explicitly.
	invalidCases := []struct {
		name   string
		cursor CursorSnapshot
		begin  int64
	}{
		{"unanchored non-zero position", CursorSnapshot{NextBlock: 3}, 0},
		{"anchor at zero position", CursorSnapshot{NextBlock: 0, LastBlockHash: blockTopic(1)}, 0},
		{"anchor hash not in chain", CursorSnapshot{NextBlock: 3, LastBlockHash: common.HexToHash("0xdead")}, 0},
		{"cursor before range begin", CursorSnapshot{NextBlock: 2, LastBlockHash: env.bc.GetCanonicalHash(1)}, 5},
		{"cursor beyond chain head", CursorSnapshot{NextBlock: newHead + 2, LastBlockHash: env.bc.GetCanonicalHash(newHead)}, 0},
		{"anchor number mismatch", CursorSnapshot{NextBlock: 4, LastBlockHash: env.bc.GetCanonicalHash(1)}, 0},
	}
	for _, tc := range invalidCases {
		t.Run(tc.name, func(t *testing.T) {
			bad := env.newCursorFilter(tc.begin, tc.cursor)
			if _, err := bad.Logs(context.Background()); !errors.Is(err, ErrInvalidCursor) {
				t.Fatalf("expected ErrInvalidCursor, got %v", err)
			}
		})
	}

	// SetCursor/Cursor on a single block filter are not supported.
	bf := env.sys.NewBlockFilter(env.bc.GetCanonicalHash(1), nil, nil)
	if err := bf.SetCursor(CursorSnapshot{NextBlock: 2, LastBlockHash: env.bc.GetCanonicalHash(1)}); !errors.Is(err, ErrCursorNotSupported) {
		t.Fatalf("block filter SetCursor: expected ErrCursorNotSupported, got %v", err)
	}
	if _, err := bf.Cursor(); !errors.Is(err, ErrCursorNotSupported) {
		t.Fatalf("block filter Cursor: expected ErrCursorNotSupported, got %v", err)
	}

	// A range filter without cursor tracking returns ErrCursorNotEnabled
	// while its behaviour remains a full range rescan.
	plain := env.sys.NewRangeFilter(0, rpc.LatestBlockNumber.Int64(), []common.Address{env.contract}, nil, 0)
	if _, err := plain.Cursor(); !errors.Is(err, ErrCursorNotEnabled) {
		t.Fatalf("plain filter Cursor: expected ErrCursorNotEnabled, got %v", err)
	}
	logs, err = plain.Logs(context.Background())
	if err != nil {
		t.Fatal("plain filter scan failed:", err)
	}
	env.assertLogs("plain filter full rescan", logs, env.expectedLogs(1, newHead, finalTopic))
}

// TestRangeFilterCursorRollback covers reorg rollback corners around the
// exact fork boundary, in both indexed and unindexed modes:
//   - a cursor anchored exactly at the fork block must resume on the new chain
//     without rescanning already confirmed blocks;
//   - a cursor ahead of the reorg point must roll back to the first block
//     after the common ancestor (never skipping old blocks);
//   - a cursor behind the reorg point keeps its position on the shared chain.
func TestRangeFilterCursorRollback(t *testing.T) {
	for _, indexed := range []bool{true, false} {
		name := "unindexed"
		if indexed {
			name = "indexed"
		}
		t.Run(name, func(t *testing.T) {
			env, teardown := newCursorTestEnv(t, indexed)
			defer teardown()

			const (
				mainN  = 7 // canonical chain initially: blocks 1..7
				forkAt = 4 // side chain forks after block 4
				sideN  = 3 // side chain blocks 5..7 (equal length, distinct content)
			)
			genesis := env.bc.Genesis()
			env.insert(env.generateBlocks(genesis, mainN, mainTopic, mainNonce))
			env.startIndexer()

			// Scan blocks 1..4 with one filter, keep its cursor at block 5...
			f4 := env.sys.NewRangeFilterWithCursor(0, int64(forkAt),
				[]common.Address{env.contract}, [][]common.Hash{nil}, 0, CursorSnapshot{})
			if _, err := f4.Logs(context.Background()); err != nil {
				t.Fatal(err)
			}
			c4, err := f4.Cursor()
			if err != nil {
				t.Fatal(err)
			}
			if c4.NextBlock != forkAt+1 {
				t.Fatalf("cursor at fork: expected next %d, got %d", forkAt+1, c4.NextBlock)
			}

			// ...and scan the whole chain with another filter, cursor at 8.
			full := env.newCursorFilter(0, CursorSnapshot{})
			if _, err := full.Logs(context.Background()); err != nil {
				t.Fatal(err)
			}
			cFull, err := full.Cursor()
			if err != nil {
				t.Fatal(err)
			}
			if cFull.NextBlock != mainN+1 {
				t.Fatalf("full cursor: expected next %d, got %d", mainN+1, cFull.NextBlock)
			}

			// Reorg at block 4: side chain 5..7 replaces old 5..7.
			side := env.generateBlocks(env.bc.GetBlockByNumber(forkAt), sideN, sideTopic, mainNonce)
			env.insert(side)
			newHead := forkAt + uint64(sideN)
			if head := env.bc.CurrentBlock().Number.Uint64(); head != newHead {
				t.Fatalf("unexpected head after reorg: %d", head)
			}

			// Cursor exactly at the fork point: its anchor (block 4) is still
			// canonical, so it scans the new chain's blocks 5..7 once.
			f := env.newCursorFilter(0, c4)
			logs, err := f.Logs(context.Background())
			if err != nil {
				t.Fatal("resume at fork point failed:", err)
			}
			env.assertLogs("resume exactly at fork point", logs, env.expectedLogs(forkAt+1, newHead, sideTopic))

			// Cursor ahead of the reorg point: rollback to block 5.
			f = env.newCursorFilter(0, cFull)
			logs, err = f.Logs(context.Background())
			if err != nil {
				t.Fatal("resume past fork point failed:", err)
			}
			env.assertLogs("rollback past fork point", logs, env.expectedLogs(forkAt+1, newHead, sideTopic))
			c, _ := f.Cursor()
			if c.NextBlock != newHead+1 {
				t.Fatalf("post-reorg cursor: expected next %d, got %d", newHead+1, c.NextBlock)
			}

			// A cursor anchored at a shared block behind the reorg point is
			// still valid and keeps its position (here: anchored at block 3,
			// resume at block 4, which is itself shared, so it must be
			// rescanned exactly once together with the side chain blocks).
			cBehind := CursorSnapshot{NextBlock: 4, LastBlockHash: env.bc.GetCanonicalHash(3)}
			f = env.newCursorFilter(0, cBehind)
			logs, err = f.Logs(context.Background())
			if err != nil {
				t.Fatal("resume behind fork point failed:", err)
			}
			want := append(env.expectedLogs(4, forkAt, mainTopic), env.expectedLogs(forkAt+1, newHead, sideTopic)...)
			env.assertLogs("resume behind fork point", logs, want)
		})
	}
}

// TestRangeFilterCursorSnapshot verifies resumable log filtering with cursor
// snapshots, reorg rollback semantics and invalid snapshot handling, using an
// in-memory chain. It is repeatable and runs against both the indexed and
// unindexed search backends.
func TestRangeFilterCursorSnapshot(t *testing.T) {
	t.Run("indexed", func(t *testing.T) { runCursorScenario(t, true) })
	t.Run("unindexed", func(t *testing.T) { runCursorScenario(t, false) })
}
