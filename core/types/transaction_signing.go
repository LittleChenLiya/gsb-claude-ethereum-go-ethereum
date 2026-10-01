// Copyright 2016 The go-ethereum Authors
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
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/params/forks"
)

var ErrInvalidChainId = errors.New("invalid chain id for signer")

// sigCache is used to cache the derived sender and contains
// the signer used to derive it.
type sigCache struct {
	signer Signer
	from   common.Address
}

// MakeSigner returns a Signer based on the given chain config and block number.
func MakeSigner(config *params.ChainConfig, blockNumber *big.Int, blockTime uint64) Signer {
	var signer Signer
	switch {
	case config.IsPrague(blockNumber, blockTime):
		signer = NewPragueSigner(config.ChainID)
	case config.IsCancun(blockNumber, blockTime):
		signer = NewCancunSigner(config.ChainID)
	case config.IsLondon(blockNumber):
		signer = NewLondonSigner(config.ChainID)
	case config.IsBerlin(blockNumber):
		signer = NewEIP2930Signer(config.ChainID)
	case config.IsEIP155(blockNumber):
		signer = NewEIP155Signer(config.ChainID)
	case config.IsHomestead(blockNumber):
		signer = HomesteadSigner{}
	default:
		signer = FrontierSigner{}
	}
	return signer
}

// LatestSigner returns the 'most permissive' Signer available for the given chain
// configuration. Specifically, this enables support of all types of transactions
// when their respective forks are scheduled to occur at any block number (or time)
// in the chain config.
//
// Use this in transaction-handling code where the current block number is unknown. If you
// have the current block number available, use MakeSigner instead.
func LatestSigner(config *params.ChainConfig) Signer {
	var signer Signer
	if config.ChainID != nil {
		switch {
		case config.PragueTime != nil:
			signer = NewPragueSigner(config.ChainID)
		case config.CancunTime != nil:
			signer = NewCancunSigner(config.ChainID)
		case config.LondonBlock != nil:
			signer = NewLondonSigner(config.ChainID)
		case config.BerlinBlock != nil:
			signer = NewEIP2930Signer(config.ChainID)
		case config.EIP155Block != nil:
			signer = NewEIP155Signer(config.ChainID)
		default:
			signer = HomesteadSigner{}
		}
	} else {
		signer = HomesteadSigner{}
	}
	return signer
}

// LatestSignerForChainID returns the 'most permissive' Signer available. Specifically,
// this enables support for EIP-155 replay protection and all implemented EIP-2718
// transaction types if chainID is non-nil.
//
// Use this in transaction-handling code where the current block number and fork
// configuration are unknown. If you have a ChainConfig, use LatestSigner instead.
// If you have a ChainConfig and know the current block number, use MakeSigner instead.
func LatestSignerForChainID(chainID *big.Int) Signer {
	var signer Signer
	if chainID != nil {
		signer = NewPragueSigner(chainID)
	} else {
		signer = HomesteadSigner{}
	}
	return signer
}

// SignTx signs the transaction using the given signer and private key.
func SignTx(tx *Transaction, s Signer, prv *ecdsa.PrivateKey) (*Transaction, error) {
	h := s.Hash(tx)
	sig, err := crypto.Sign(h[:], prv)
	if err != nil {
		return nil, err
	}
	return tx.WithSignature(s, sig)
}

// SignNewTx creates a transaction and signs it.
func SignNewTx(prv *ecdsa.PrivateKey, s Signer, txdata TxData) (*Transaction, error) {
	return SignTx(NewTx(txdata), s, prv)
}

// MustSignNewTx creates a transaction and signs it.
// This panics if the transaction cannot be signed.
func MustSignNewTx(prv *ecdsa.PrivateKey, s Signer, txdata TxData) *Transaction {
	tx, err := SignNewTx(prv, s, txdata)
	if err != nil {
		panic(err)
	}
	return tx
}

// Sender returns the address derived from the signature (V, R, S) using secp256k1
// elliptic curve and an error if it failed deriving or upon an incorrect
// signature.
//
// Sender may cache the address, allowing it to be used regardless of
// signing method. The cache is invalidated if the cached signer does
// not match the signer used in the current call.
func Sender(signer Signer, tx *Transaction) (common.Address, error) {
	if sigCache := tx.from.Load(); sigCache != nil {
		// If the signer used to derive from in a previous
		// call is not the same as used current, invalidate
		// the cache.
		if sigCache.signer.Equal(signer) {
			return sigCache.from, nil
		}
	}

	addr, err := signer.Sender(tx)
	if err != nil {
		return common.Address{}, err
	}
	tx.from.Store(&sigCache{signer: signer, from: addr})
	return addr, nil
}

// SigningDomain is the replay-protection domain a transaction signature is
// bound to. It ties together the chain ID, the transaction type and the hash
// that must be (or was) signed with the sender's private key.
type SigningDomain struct {
	ChainID *big.Int    // chain the signature is bound to; zero for unprotected legacy transactions
	Type    uint8       // transaction type, see LegacyTxType ... SetCodeTxType
	SigHash common.Hash // hash that is signed for this domain
}

// CheckSigningDomain verifies that the transaction belongs to the signature
// domain of the given chain. It checks that:
//
//   - the transaction type is known and the type byte matches the inner
//     transaction encoding,
//   - the chain ID bound to the signature matches the expected chain ID,
//     rejecting cross-chain replay attempts with ErrInvalidChainId,
//   - and computes the hash that must be signed using the historical
//     encodings: legacy transactions use the RLP preimage (EIP-155 for
//     replay-protected transactions, plain RLP otherwise), typed
//     transactions use their EIP-2718 type-prefixed preimage.
//
// Unprotected legacy transactions (pre-EIP-155) carry no chain ID and are
// valid on every chain; they cannot be replay-protected and report a zero
// chain ID.
//
// The returned domain's SigHash is the hash that must be signed for the
// expected chain. A signature produced for another chain or another
// transaction type recovers a different sender over that hash, so the chain
// ID and type checks are what enforce replay protection on top of signature
// recovery.
func (tx *Transaction) CheckSigningDomain(chainID *big.Int) (SigningDomain, error) {
	if chainID == nil {
		chainID = new(big.Int)
	}
	if tx == nil || tx.inner == nil {
		return SigningDomain{ChainID: new(big.Int)}, ErrTxTypeNotSupported
	}
	domain := SigningDomain{ChainID: new(big.Int), Type: tx.Type()}

	// The type byte must match the inner transaction encoding and be a known
	// transaction type.
	if tx.inner.txType() != domain.Type {
		return domain, fmt.Errorf("%w: type byte %d does not match inner encoding", ErrTxTypeNotSupported, domain.Type)
	}
	switch tx.inner.(type) {
	case *LegacyTx, *AccessListTx, *DynamicFeeTx, *BlobTx, *SetCodeTx:
	default:
		return domain, fmt.Errorf("%w: unknown transaction type %d", ErrTxTypeNotSupported, domain.Type)
	}

	switch inner := tx.inner.(type) {
	case *LegacyTx:
		if tx.Protected() {
			// Replay-protected legacy transactions derive the chain ID from V
			// and sign the EIP-155 RLP preimage.
			domain.ChainID.Set(tx.ChainId())
			domain.SigHash = inner.sigHash(chainID)
			if domain.ChainID.Cmp(chainID) != 0 {
				return domain, fmt.Errorf("%w: have %d want %d", ErrInvalidChainId, domain.ChainID, chainID)
			}
		} else {
			// Historical pre-EIP-155 encoding: plain RLP, no chain ID. The
			// signature is valid on every chain, so there is no domain to
			// check against.
			domain.SigHash = FrontierSigner{}.Hash(tx)
		}
	default:
		// Typed transactions (EIP-2718 and later) carry an explicit chain ID
		// and sign the type-prefixed RLP preimage.
		domain.ChainID.Set(tx.ChainId())
		domain.SigHash = inner.sigHash(chainID)
		if domain.ChainID.Sign() == 0 {
			return domain, fmt.Errorf("%w: missing chain id in typed transaction", ErrInvalidChainId)
		}
		if domain.ChainID.Cmp(chainID) != 0 {
			return domain, fmt.Errorf("%w: have %d want %d", ErrInvalidChainId, domain.ChainID, chainID)
		}
	}
	return domain, nil
}

// Signer encapsulates transaction signature handling. The name of this type is slightly
// misleading because Signers don't actually sign, they're just for validating and
// processing of signatures.
//
// Note that this interface is not a stable API and may change at any time to accommodate
// new protocol rules.
type Signer interface {
	// Sender returns the sender address of the transaction.
	Sender(tx *Transaction) (common.Address, error)

	// SignatureValues returns the raw R, S, V values corresponding to the
	// given signature.
	SignatureValues(tx *Transaction, sig []byte) (r, s, v *big.Int, err error)
	ChainID() *big.Int

	// Hash returns 'signature hash', i.e. the transaction hash that is signed by the
	// private key. This hash does not uniquely identify the transaction.
	Hash(tx *Transaction) common.Hash

	// Equal returns true if the given signer is the same as the receiver.
	Equal(Signer) bool
}

// modernSigner is the signer implementation that handles non-legacy transaction types.
// For legacy transactions, it defers to one of the legacy signers (frontier, homestead, eip155).
type modernSigner struct {
	txtypes txtypeSet
	chainID *big.Int
	legacy  Signer
}

// txtypeSet is a bitmap for transaction types.
type txtypeSet [2]uint64

func (v *txtypeSet) set(txType byte) {
	v[txType/64] |= 1 << (txType % 64)
}

func (v *txtypeSet) has(txType byte) bool {
	if txType >= byte(len(v)*64) {
		return false
	}
	return v[txType/64]&(1<<(txType%64)) != 0
}

func newModernSigner(chainID *big.Int, fork forks.Fork) Signer {
	if chainID == nil || chainID.Sign() <= 0 {
		panic(fmt.Sprintf("invalid chainID %v", chainID))
	}
	s := &modernSigner{
		chainID: chainID,
	}
	// configure legacy signer
	switch {
	case fork >= forks.SpuriousDragon:
		s.legacy = NewEIP155Signer(chainID)
	case fork >= forks.Homestead:
		s.legacy = HomesteadSigner{}
	default:
		s.legacy = FrontierSigner{}
	}
	s.txtypes.set(LegacyTxType)
	// configure tx types
	if fork >= forks.Berlin {
		s.txtypes.set(AccessListTxType)
	}
	if fork >= forks.London {
		s.txtypes.set(DynamicFeeTxType)
	}
	if fork >= forks.Cancun {
		s.txtypes.set(BlobTxType)
	}
	if fork >= forks.Prague {
		s.txtypes.set(SetCodeTxType)
	}
	return s
}

func (s *modernSigner) ChainID() *big.Int {
	return s.chainID
}

func (s *modernSigner) Equal(s2 Signer) bool {
	other, ok := s2.(*modernSigner)
	return ok && s.chainID.Cmp(other.chainID) == 0 && s.txtypes == other.txtypes && s.legacy.Equal(other.legacy)
}

func (s *modernSigner) Hash(tx *Transaction) common.Hash {
	return tx.inner.sigHash(s.chainID)
}

func (s *modernSigner) supportsType(txtype byte) bool {
	return s.txtypes.has(txtype)
}

func (s *modernSigner) Sender(tx *Transaction) (common.Address, error) {
	tt := tx.Type()
	if !s.supportsType(tt) {
		return common.Address{}, ErrTxTypeNotSupported
	}
	if tt == LegacyTxType {
		return s.legacy.Sender(tx)
	}
	if tx.ChainId().Cmp(s.chainID) != 0 {
		return common.Address{}, fmt.Errorf("%w: have %d want %d", ErrInvalidChainId, tx.ChainId(), s.chainID)
	}
	// 'modern' txs are defined to use 0 and 1 as their recovery
	// id, add 27 to become equivalent to unprotected Homestead signatures.
	V, R, S := tx.RawSignatureValues()
	V = new(big.Int).Add(V, big.NewInt(27))
	return recoverPlain(s.Hash(tx), R, S, V, true)
}

func (s *modernSigner) SignatureValues(tx *Transaction, sig []byte) (R, S, V *big.Int, err error) {
	tt := tx.Type()
	if !s.supportsType(tt) {
		return nil, nil, nil, ErrTxTypeNotSupported
	}
	if tt == LegacyTxType {
		return s.legacy.SignatureValues(tx, sig)
	}
	// Check that chain ID of tx matches the signer. We also accept ID zero here,
	// because it indicates that the chain ID was not specified in the tx.
	if tx.inner.chainID().Sign() != 0 && tx.inner.chainID().Cmp(s.chainID) != 0 {
		return nil, nil, nil, fmt.Errorf("%w: have %d want %d", ErrInvalidChainId, tx.inner.chainID(), s.chainID)
	}
	R, S, _, err = decodeSignature(sig)
	if err != nil {
		return nil, nil, nil, err
	}
	V = big.NewInt(int64(sig[64]))
	return R, S, V, nil
}

// NewPragueSigner returns a signer that accepts
// - EIP-7702 set code transactions
// - EIP-4844 blob transactions
// - EIP-1559 dynamic fee transactions
// - EIP-2930 access list transactions,
// - EIP-155 replay protected transactions, and
// - legacy Homestead transactions.
func NewPragueSigner(chainId *big.Int) Signer {
	return newModernSigner(chainId, forks.Prague)
}

// NewCancunSigner returns a signer that accepts
// - EIP-4844 blob transactions
// - EIP-1559 dynamic fee transactions
// - EIP-2930 access list transactions,
// - EIP-155 replay protected transactions, and
// - legacy Homestead transactions.
func NewCancunSigner(chainId *big.Int) Signer {
	return newModernSigner(chainId, forks.Cancun)
}

// NewLondonSigner returns a signer that accepts
// - EIP-1559 dynamic fee transactions
// - EIP-2930 access list transactions,
// - EIP-155 replay protected transactions, and
// - legacy Homestead transactions.
func NewLondonSigner(chainId *big.Int) Signer {
	return newModernSigner(chainId, forks.London)
}

// NewEIP2930Signer returns a signer that accepts EIP-2930 access list transactions,
// EIP-155 replay protected transactions, and legacy Homestead transactions.
func NewEIP2930Signer(chainId *big.Int) Signer {
	return newModernSigner(chainId, forks.Berlin)
}

// EIP155Signer implements Signer using the EIP-155 rules. This accepts transactions which
// are replay-protected as well as unprotected homestead transactions.
// Deprecated: always use the Signer interface type
type EIP155Signer struct {
	chainId *big.Int
}

func NewEIP155Signer(chainId *big.Int) EIP155Signer {
	if chainId == nil {
		chainId = new(big.Int)
	}
	return EIP155Signer{
		chainId: chainId,
	}
}

func (s EIP155Signer) ChainID() *big.Int {
	return s.chainId
}

func (s EIP155Signer) Equal(s2 Signer) bool {
	eip155, ok := s2.(EIP155Signer)
	return ok && eip155.chainId.Cmp(s.chainId) == 0
}

var big8 = big.NewInt(8)

func (s EIP155Signer) Sender(tx *Transaction) (common.Address, error) {
	if tx.Type() != LegacyTxType {
		return common.Address{}, ErrTxTypeNotSupported
	}
	if !tx.Protected() {
		return HomesteadSigner{}.Sender(tx)
	}
	if tx.ChainId().Cmp(s.chainId) != 0 {
		return common.Address{}, fmt.Errorf("%w: have %d want %d", ErrInvalidChainId, tx.ChainId(), s.chainId)
	}
	V, R, S := tx.RawSignatureValues()
	V = new(big.Int).Sub(V, s.chainId)
	V = new(big.Int).Sub(V, s.chainId)
	V.Sub(V, big8)
	return recoverPlain(s.Hash(tx), R, S, V, true)
}

// SignatureValues returns signature values. This signature
// needs to be in the [R || S || V] format where V is 0 or 1.
func (s EIP155Signer) SignatureValues(tx *Transaction, sig []byte) (R, S, V *big.Int, err error) {
	if tx.Type() != LegacyTxType {
		return nil, nil, nil, ErrTxTypeNotSupported
	}
	R, S, V, err = decodeSignature(sig)
	if err != nil {
		return nil, nil, nil, err
	}
	if s.chainId.Sign() != 0 {
		V = big.NewInt(int64(sig[64] + 35))
		V.Add(V, s.chainId)
		V.Add(V, s.chainId)
	}
	return R, S, V, nil
}

// Hash returns the hash to be signed by the sender.
// It does not uniquely identify the transaction.
func (s EIP155Signer) Hash(tx *Transaction) common.Hash {
	return tx.inner.sigHash(s.chainId)
}

// HomesteadSigner implements Signer using the homestead rules. The only valid reason to
// use this type is creating legacy transactions which are intentionally not
// replay-protected.
type HomesteadSigner struct{ FrontierSigner }

func (hs HomesteadSigner) ChainID() *big.Int {
	return nil
}

func (hs HomesteadSigner) Equal(s2 Signer) bool {
	_, ok := s2.(HomesteadSigner)
	return ok
}

// SignatureValues returns signature values. This signature
// needs to be in the [R || S || V] format where V is 0 or 1.
func (hs HomesteadSigner) SignatureValues(tx *Transaction, sig []byte) (r, s, v *big.Int, err error) {
	return hs.FrontierSigner.SignatureValues(tx, sig)
}

func (hs HomesteadSigner) Sender(tx *Transaction) (common.Address, error) {
	if tx.Type() != LegacyTxType {
		return common.Address{}, ErrTxTypeNotSupported
	}
	v, r, s := tx.RawSignatureValues()
	return recoverPlain(hs.Hash(tx), r, s, v, true)
}

// FrontierSigner implements Signer using the frontier rules.
// Deprecated: always use the Signer interface type
type FrontierSigner struct{}

func (fs FrontierSigner) ChainID() *big.Int {
	return nil
}

func (fs FrontierSigner) Equal(s2 Signer) bool {
	_, ok := s2.(FrontierSigner)
	return ok
}

func (fs FrontierSigner) Sender(tx *Transaction) (common.Address, error) {
	if tx.Type() != LegacyTxType {
		return common.Address{}, ErrTxTypeNotSupported
	}
	v, r, s := tx.RawSignatureValues()
	return recoverPlain(fs.Hash(tx), r, s, v, false)
}

// SignatureValues returns signature values. This signature
// needs to be in the [R || S || V] format where V is 0 or 1.
func (fs FrontierSigner) SignatureValues(tx *Transaction, sig []byte) (r, s, v *big.Int, err error) {
	if tx.Type() != LegacyTxType {
		return nil, nil, nil, ErrTxTypeNotSupported
	}
	r, s, v, err = decodeSignature(sig)
	return r, s, v, err
}

// Hash returns the hash to be signed by the sender.
// It does not uniquely identify the transaction.
func (fs FrontierSigner) Hash(tx *Transaction) common.Hash {
	return rlpHash([]any{
		tx.Nonce(),
		tx.GasPrice(),
		tx.Gas(),
		tx.To(),
		tx.Value(),
		tx.Data(),
	})
}

func decodeSignature(sig []byte) (r, s, v *big.Int, err error) {
	if len(sig) != crypto.SignatureLength {
		return nil, nil, nil, fmt.Errorf("wrong size for signature: got %d, want %d", len(sig), crypto.SignatureLength)
	}
	r = new(big.Int).SetBytes(sig[:32])
	s = new(big.Int).SetBytes(sig[32:64])
	v = new(big.Int).SetBytes([]byte{sig[64] + 27})
	return r, s, v, nil
}

func recoverPlain(sighash common.Hash, R, S, Vb *big.Int, homestead bool) (common.Address, error) {
	if Vb.BitLen() > 8 {
		return common.Address{}, ErrInvalidSig
	}
	V := byte(Vb.Uint64() - 27)
	if !crypto.ValidateSignatureValues(V, R, S, homestead) {
		return common.Address{}, ErrInvalidSig
	}
	// encode the signature in uncompressed format
	r, s := R.Bytes(), S.Bytes()
	sig := make([]byte, crypto.SignatureLength)
	copy(sig[32-len(r):32], r)
	copy(sig[64-len(s):64], s)
	sig[64] = V
	// recover the public key from the signature
	pub, err := crypto.Ecrecover(sighash[:], sig)
	if err != nil {
		return common.Address{}, err
	}
	if len(pub) == 0 || pub[0] != 4 {
		return common.Address{}, errors.New("invalid public key")
	}
	var addr common.Address
	copy(addr[:], crypto.Keccak256(pub[1:])[12:])
	return addr, nil
}

// deriveChainId derives the chain id from the given v parameter
func deriveChainId(v *big.Int) *big.Int {
	if v.BitLen() <= 64 {
		v := v.Uint64()
		if v == 27 || v == 28 {
			return new(big.Int)
		}
		return new(big.Int).SetUint64((v - 35) / 2)
	}
	vCopy := new(big.Int).Sub(v, big.NewInt(35))
	return vCopy.Rsh(vCopy, 1)
}
