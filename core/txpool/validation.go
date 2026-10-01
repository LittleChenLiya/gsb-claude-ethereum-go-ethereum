// Copyright 2023 The go-ethereum Authors
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

package txpool

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto/kzg4844"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

var (
	// blobTxMinBlobGasPrice is the big.Int version of the configured protocol
	// parameter to avoid constructing a new big integer for every transaction.
	blobTxMinBlobGasPrice = big.NewInt(params.BlobTxMinBlobGasprice)
)

// ValidationOptions define certain differences between transaction validation
// across the different pools without having to duplicate those checks.
type ValidationOptions struct {
	Config *params.ChainConfig // Chain configuration to selectively validate based on current fork rules

	Accept       uint8    // Bitmap of transaction types that should be accepted for the calling pool
	MaxSize      uint64   // Maximum size of a transaction that the caller can meaningfully handle
	MaxBlobCount int      // Maximum number of blobs allowed per transaction
	MinTip       *big.Int // Minimum gas tip needed to allow a transaction into the caller pool
}

// ValidationFunction is an method type which the pools use to perform the tx-validations which do not
// require state access. Production code typically uses ValidateTransaction, whereas testing-code
// might choose to instead use something else, e.g. to always fail or avoid heavy cpu usage.
type ValidationFunction func(tx *types.Transaction, head *types.Header, signer types.Signer, opts *ValidationOptions) error

// ValidateTransaction is a helper method to check whether a transaction is valid
// according to the consensus rules, but does not check state-dependent validation
// (balance, nonce, etc).
//
// This check is public to allow different transaction pools to check the basic
// rules without duplicating code and running the risk of missed updates.
func ValidateTransaction(tx *types.Transaction, head *types.Header, signer types.Signer, opts *ValidationOptions) error {
	// Ensure transactions not implemented by the calling pool are rejected
	if opts.Accept&(1<<tx.Type()) == 0 {
		return fmt.Errorf("%w: tx type %v not supported by this pool", core.ErrTxTypeNotSupported, tx.Type())
	}
	// Before performing any expensive validations, sanity check that the tx is
	// smaller than the maximum limit the pool can meaningfully handle
	if tx.Size() > opts.MaxSize {
		return fmt.Errorf("%w: transaction size %v, limit %v", ErrOversizedData, tx.Size(), opts.MaxSize)
	}
	// Ensure only transactions that have been enabled are accepted
	rules := opts.Config.Rules(head.Number, head.Difficulty.Sign() == 0, head.Time)
	if !rules.IsBerlin && tx.Type() != types.LegacyTxType {
		return fmt.Errorf("%w: type %d rejected, pool not yet in Berlin", core.ErrTxTypeNotSupported, tx.Type())
	}
	if !rules.IsLondon && tx.Type() == types.DynamicFeeTxType {
		return fmt.Errorf("%w: type %d rejected, pool not yet in London", core.ErrTxTypeNotSupported, tx.Type())
	}
	if !rules.IsCancun && tx.Type() == types.BlobTxType {
		return fmt.Errorf("%w: type %d rejected, pool not yet in Cancun", core.ErrTxTypeNotSupported, tx.Type())
	}
	if !rules.IsPrague && tx.Type() == types.SetCodeTxType {
		return fmt.Errorf("%w: type %d rejected, pool not yet in Prague", core.ErrTxTypeNotSupported, tx.Type())
	}
	// Check whether the init code size has been exceeded
	if tx.To() == nil {
		if err := vm.CheckMaxInitCodeSize(&rules, uint64(len(tx.Data()))); err != nil {
			return err
		}
	}
	if rules.IsOsaka && !rules.IsAmsterdam && tx.Gas() > params.MaxTxGas {
		return fmt.Errorf("%w (cap: %d, tx: %d)", core.ErrGasLimitTooHigh, params.MaxTxGas, tx.Gas())
	}
	// Transactions can't be negative. This may never happen using RLP decoded
	// transactions but may occur for transactions created using the RPC.
	if tx.Value().Sign() < 0 {
		return ErrNegativeValue
	}
	// Ensure the transaction doesn't exceed the current block limit gas
	if head.GasLimit < tx.Gas() {
		return ErrGasLimit
	}
	// Sanity check for extremely large numbers (supported by RLP or RPC)
	if tx.GasFeeCap().BitLen() > 256 {
		return core.ErrFeeCapVeryHigh
	}
	if tx.GasTipCap().BitLen() > 256 {
		return core.ErrTipVeryHigh
	}
	// Ensure gasFeeCap is greater than or equal to gasTipCap
	if tx.GasFeeCapIntCmp(tx.GasTipCap()) < 0 {
		return core.ErrTipAboveFeeCap
	}
	// Make sure the transaction is signed properly
	from, err := types.Sender(signer, tx)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidSender, err)
	}
	// Limit nonce to 2^64-1 per EIP-2681
	if tx.Nonce()+1 < tx.Nonce() {
		return core.ErrNonceMax
	}
	// Sanity check for extremely large numbers (supported by RLP or RPC)
	value, overflow := uint256.FromBig(tx.Value())
	if overflow {
		return core.ErrInsufficientFunds
	}
	// Ensure the transaction has more gas than the bare minimum needed to cover
	// the transaction metadata
	intrGas, err := core.IntrinsicGas(tx.Data(), tx.AccessList(), tx.SetCodeAuthorizations(), from, tx.To(), value, rules)
	if err != nil {
		return err
	}
	if tx.Gas() < intrGas {
		return fmt.Errorf("%w: gas %v, minimum needed %v", core.ErrIntrinsicGas, tx.Gas(), intrGas)
	}
	// Ensure the transaction can cover floor data gas.
	if rules.IsPrague {
		floorDataGas, err := core.FloorDataGas(rules, from, tx.To(), value, tx.Data(), tx.AccessList())
		if err != nil {
			return err
		}
		// Make sure the transaction has sufficient gas allowance to
		// pay the floor cost.
		if tx.Gas() < floorDataGas {
			return fmt.Errorf("%w: gas %v, minimum needed %v", core.ErrFloorDataGas, tx.Gas(), floorDataGas)
		}
		// In Amsterdam, the transaction gas limit is allowed to exceed
		// params.MaxTxGas, but the calldata floor cost is capped by it.
		if rules.IsAmsterdam && max(intrGas, floorDataGas) > params.MaxTxGas {
			return fmt.Errorf("%w: intrinsic cost %v, floor: %v", core.ErrFloorDataGas, intrGas, floorDataGas)
		}
	}
	// Ensure the gasprice is high enough to cover the requirement of the calling pool
	if tx.GasTipCapIntCmp(opts.MinTip) < 0 {
		return fmt.Errorf("%w: gas tip cap %v, minimum needed %v", ErrTxGasPriceTooLow, tx.GasTipCap(), opts.MinTip)
	}
	if tx.Type() == types.BlobTxType {
		return validateBlobSidecar(tx, head, opts)
	}
	if tx.Type() == types.SetCodeTxType {
		if len(tx.SetCodeAuthorizations()) == 0 {
			return errors.New("set code tx must have at least one authorization tuple")
		}
	}
	return nil
}

// validateBlobSidecar implements the blob sidecar validation.
// Note that this doesn't verify the consistency between blobs(cells) and
// proofs. For proof verification, use validateCells.
func validateBlobSidecar(tx *types.Transaction, head *types.Header, opts *ValidationOptions) error {
	if tx.BlobGasFeeCapIntCmp(blobTxMinBlobGasPrice) < 0 {
		return fmt.Errorf("%w: blob fee cap %v, minimum needed %v", ErrTxGasPriceTooLow, tx.BlobGasFeeCap(), blobTxMinBlobGasPrice)
	}
	sidecar := tx.BlobTxSidecar()
	if sidecar == nil {
		return errors.New("missing sidecar in blob transaction")
	}
	hashes := tx.BlobHashes()
	if err := sidecar.ValidateBlobCommitmentHashes(hashes); err != nil {
		return err
	}
	if len(hashes) > opts.MaxBlobCount {
		return fmt.Errorf("%w: blob count %v, limit %v", ErrTxBlobLimitExceeded, len(hashes), opts.MaxBlobCount)
	}
	if sidecar.Version != types.BlobSidecarVersion1 {
		return fmt.Errorf("%w: unexpected sidecar version, want: %d, got: %d", ErrSidecarFormatError, types.BlobSidecarVersion1, sidecar.Version)
	}
	if len(sidecar.Proofs) != len(sidecar.Commitments)*kzg4844.CellProofsPerBlob {
		return fmt.Errorf("%w: invalid number of %d blob proofs expected %d", ErrSidecarFormatError, len(sidecar.Proofs), len(sidecar.Commitments)*kzg4844.CellProofsPerBlob)
	}
	return nil
}

func ValidateCells(sidecar *types.BlobTxCellSidecar) error {
	// Two checks here (custody count check and blobCount check) is duplicated in buffer.go
	// However it is required to 1) serve eth71 peer and direct submission 2) catch any bug in
	// merging cell delivery.
	if sidecar.Custody.OneCount() == 0 {
		return errors.New("blobless blob transaction")
	}
	// Verify whether the blob count is consistent with other parts of the sidecar and the transaction
	blobCount := len(sidecar.Cells) / sidecar.Custody.OneCount()
	if blobCount == 0 {
		return errors.New("blobless blob transaction")
	}
	if blobCount != len(sidecar.Commitments) {
		return fmt.Errorf("invalid number of %d blobs compared to %d commitments", blobCount, len(sidecar.Commitments))
	}
	if len(sidecar.Proofs) != len(sidecar.Commitments)*kzg4844.CellProofsPerBlob {
		return fmt.Errorf("invalid number of %d proofs compared to %d commitments", len(sidecar.Proofs), len(sidecar.Commitments))
	}
	if sidecar.Version != types.BlobSidecarVersion1 {
		return fmt.Errorf("unexpected sidecar version, want: %d, got: %d", types.BlobSidecarVersion1, sidecar.Version)
	}
	return validateCellsOsaka(sidecar)
}

func validateCellsOsaka(sidecar *types.BlobTxCellSidecar) error {
	indices := sidecar.Custody.Indices()
	cellProofs := make([]kzg4844.Proof, 0)
	for blobIdx := range len(sidecar.Commitments) {
		for _, proofIdx := range indices {
			idx := blobIdx*kzg4844.CellProofsPerBlob + int(proofIdx)
			cellProofs = append(cellProofs, sidecar.Proofs[idx])
		}
	}
	if err := kzg4844.VerifyCells(sidecar.Cells, sidecar.Commitments, cellProofs, sidecar.Custody.Indices()); err != nil {
		return fmt.Errorf("%w: %v", ErrKZGVerificationError, err)
	}
	return nil
}

// ValidationOptionsWithState define certain differences between stateful transaction
// validation across the different pools without having to duplicate those checks.
type ValidationOptionsWithState struct {
	State *state.StateDB // State database to check nonces and balances against

	// FirstNonceGap is an optional callback to retrieve the first nonce gap in
	// the list of pooled transactions of a specific account. If this method is
	// set, nonce gaps will be checked and forbidden. If this method is not set,
	// nonce gaps will be ignored and permitted.
	FirstNonceGap func(addr common.Address) uint64

	// UsedAndLeftSlots is an optional callback to retrieve the number of tx slots
	// used and the number still permitted for an account. New transactions will
	// be rejected once the number of remaining slots reaches zero.
	UsedAndLeftSlots func(addr common.Address) (int, int)

	// ExistingExpenditure is a mandatory callback to retrieve the cumulative
	// cost of the already pooled transactions to check for overdrafts.
	ExistingExpenditure func(addr common.Address) *big.Int

	// ExistingCost is a mandatory callback to retrieve an already pooled
	// transaction's cost with the given nonce to check for overdrafts.
	ExistingCost func(addr common.Address, nonce uint64) *big.Int
}

// ValidateTransactionWithState is a helper method to check whether a transaction
// is valid according to the pool's internal state checks (balance, nonce, gaps).
//
// This check is public to allow different transaction pools to check the stateful
// rules without duplicating code and running the risk of missed updates.
func ValidateTransactionWithState(tx *types.Transaction, signer types.Signer, opts *ValidationOptionsWithState) error {
	// Ensure the transaction adheres to nonce ordering
	from, err := types.Sender(signer, tx) // already validated (and cached), but cleaner to check
	if err != nil {
		log.Error("Transaction sender recovery failed", "err", err)
		return err
	}
	next := opts.State.GetNonce(from)
	if next > tx.Nonce() {
		return fmt.Errorf("%w: next nonce %v, tx nonce %v", core.ErrNonceTooLow, next, tx.Nonce())
	}
	// Ensure the transaction doesn't produce a nonce gap in pools that do not
	// support arbitrary orderings
	if opts.FirstNonceGap != nil {
		if gap := opts.FirstNonceGap(from); gap < tx.Nonce() {
			return fmt.Errorf("%w: tx nonce %v, gapped nonce %v", core.ErrNonceTooHigh, tx.Nonce(), gap)
		}
	}
	// Ensure the transactor has enough funds to cover the transaction costs
	var (
		balance = opts.State.GetBalance(from).ToBig()
		cost    = tx.Cost()
	)
	if balance.Cmp(cost) < 0 {
		return fmt.Errorf("%w: balance %v, tx cost %v, overshot %v", core.ErrInsufficientFunds, balance, cost, new(big.Int).Sub(cost, balance))
	}
	// Ensure the transactor has enough funds to cover for replacements or nonce
	// expansions without overdrafts
	spent := opts.ExistingExpenditure(from)
	if prev := opts.ExistingCost(from, tx.Nonce()); prev != nil {
		bump := new(big.Int).Sub(cost, prev)
		need := new(big.Int).Add(spent, bump)
		if balance.Cmp(need) < 0 {
			return fmt.Errorf("%w: balance %v, queued cost %v, tx bumped %v, overshot %v", core.ErrInsufficientFunds, balance, spent, bump, new(big.Int).Sub(need, balance))
		}
	} else {
		need := new(big.Int).Add(spent, cost)
		if balance.Cmp(need) < 0 {
			return fmt.Errorf("%w: balance %v, queued cost %v, tx cost %v, overshot %v", core.ErrInsufficientFunds, balance, spent, cost, new(big.Int).Sub(need, balance))
		}
		// Transaction takes a new nonce value out of the pool. Ensure it doesn't
		// overflow the number of permitted transactions from a single account
		// (i.e. max cancellable via out-of-bound transaction).
		if opts.UsedAndLeftSlots != nil {
			if used, left := opts.UsedAndLeftSlots(from); left <= 0 {
				return fmt.Errorf("%w: pooled %d txs", ErrAccountLimitExceeded, used)
			}
		}
	}
	return nil
}

// ReplaceReason identifies the first pool constraint that would reject a
// transaction replacement candidate.
type ReplaceReason uint8

const (
	// ReplaceAccepted means the candidate would be accepted by the pool,
	// either as a new transaction or as a replacement.
	ReplaceAccepted ReplaceReason = iota

	// ReplaceReasonPrice means the candidate is rejected because it does not
	// meet the configured price bump over the transaction it would replace.
	ReplaceReasonPrice

	// ReplaceReasonNonce means the candidate is rejected because of nonce
	// ordering, e.g. a gapped (future) transaction trying to replace a
	// pending one.
	ReplaceReasonNonce

	// ReplaceReasonCapacity means the candidate is rejected because the pool
	// or account has no capacity for it.
	ReplaceReasonCapacity
)

// String returns the name of the replacement reason.
func (r ReplaceReason) String() string {
	switch r {
	case ReplaceAccepted:
		return "accepted"
	case ReplaceReasonPrice:
		return "price"
	case ReplaceReasonNonce:
		return "nonce"
	case ReplaceReasonCapacity:
		return "capacity"
	default:
		return "unknown"
	}
}

// ReplaceReport is the result of a read-only replacement validation. It
// describes whether a candidate transaction would be accepted by the pool
// and, if not, which constraint rejects it first. It never modifies pool
// state.
type ReplaceReport struct {
	// Reason is the first constraint that rejects the candidate, or
	// ReplaceAccepted if the candidate would be accepted.
	Reason ReplaceReason

	// Err is the error the pool would return to the caller for the candidate
	// (nil if it would be accepted). Existing error codes are preserved.
	Err error
}

// ReplaceValidationOptions are the pool-provided facts used by
// ValidateReplacement to decide which constraint rejects a candidate first.
// Every callback must be safe to invoke without mutating pool state.
type ReplaceValidationOptions struct {
	// PoolFull reports whether admitting the candidate would overflow the
	// pool.
	PoolFull func(tx *types.Transaction) bool

	// Underpriced reports whether the candidate is cheaper than the worst
	// pooled transaction. Only consulted when the pool is full.
	Underpriced func(tx *types.Transaction) bool

	// Throttled reports whether the pool has performed too many evictions
	// since the last reorg. Only consulted when the pool is full.
	Throttled func(tx *types.Transaction) bool

	// Evictable reports whether enough underpriced transactions can be
	// evicted to make room for the candidate. Only consulted when the pool
	// is full.
	Evictable func(tx *types.Transaction) bool

	// EvictionReplacesPending reports whether evicting underpriced
	// transactions would drop a pending transaction while the candidate is
	// gapped (a future transaction trying to replace a pending one). Only
	// consulted when the pool is full and eviction is possible.
	EvictionReplacesPending func(tx *types.Transaction) bool

	// PriceBumpMet reports whether the candidate meets the configured price
	// bump over the transaction it would replace (pending or queued).
	PriceBumpMet func(tx *types.Transaction) bool
}

// ValidateReplacement runs a read-only replacement validation against the
// given pool facts and returns the first constraint that would reject the
// candidate, or ReplaceAccepted if it would be accepted.
//
// The check order mirrors the pools' admission flow: capacity constraints are
// evaluated first (underpriced, throttled, eviction, then gapped-nonce),
// followed by the price-bump requirement. Existing error codes and
// replacement priorities are preserved by the caller.
func ValidateReplacement(tx *types.Transaction, opts *ReplaceValidationOptions) ReplaceReason {
	if opts.PoolFull(tx) {
		if opts.Underpriced(tx) {
			return ReplaceReasonCapacity
		}
		if opts.Throttled(tx) {
			return ReplaceReasonCapacity
		}
		if !opts.Evictable(tx) {
			return ReplaceReasonCapacity
		}
		if opts.EvictionReplacesPending(tx) {
			return ReplaceReasonNonce
		}
	}
	if !opts.PriceBumpMet(tx) {
		return ReplaceReasonPrice
	}
	return ReplaceAccepted
}
