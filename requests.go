package spvwallet

import (
	"errors"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

var (
	ErrUnrequested     = errors.New("Unrequested header.")
	ErrNoKnownPrevious = errors.New("No previous header stored.")
)

// blockRequests keeps track of the set of blocks requested from the
// sync peer. It is capable of processing block headers out-of-order
// by saving headers that are not connected to the current best
// header until it has a connected chain. It is unavoidable that
// headers will sometimes come out-of-order and it's necessary to
// have a means of
type blockRequests struct {
	requested map[chainhash.Hash]struct{}
	received  []*wire.MsgMerkleBlock
}

// reset resets the blockRequests in an initial state. This is used
// when we have to disconnect from a peer and have to continue syncing
// from another one.
func (bc *blockRequests) reset() {
	bc.requested = make(map[chainhash.Hash]struct{})
	bc.received = nil
}

// add registers a new block that was requested from the peer.
func (bc *blockRequests) add(hash *chainhash.Hash) {
	bc.requested[*hash] = struct{}{}
}

// empty says whether the queue is empty or not.
func (bc *blockRequests) empty() bool {
	return len(bc.requested) == 0
}

// process takes a new merkle block message and a function f that is used to
// process it. The function f can assume that all blocks are fed to it in
// order, even if the blocks are processed out-of-order. It is not concurrent
// safe on its own.
func (bc *blockRequests) process(best *chainhash.Hash, m *wire.MsgMerkleBlock,
	f func(m *wire.MsgMerkleBlock) error) (err error) {
	hash := m.Header.BlockHash()

	// Was this block requested?
	if _, exists := bc.requested[hash]; !exists {
		return ErrUnrequested
	}

	// Eliminate the record of the request.
	delete(bc.requested, m.Header.BlockHash())

	// This code block handles the case that happens nearly all the time.
	// The header was given to us in the correct order, so it follows
	// the current best and can be processed immediately.
	if m.Header.PrevBlock.IsEqual(best) {
		return f(m)
	}

	// Otherwise, add this block header to the list of headers received.
	bc.received = append(bc.received, m)

	// Keep track of how many unprocessed blocks their are left in the list.
	unprocessed := len(bc.received)

	// loop through the list until we can't find one that
	for {
		var next *wire.MsgMerkleBlock
		for i, r := range bc.received {
			if r != nil && r.Header.PrevBlock.IsEqual(best) {
				next = r
				bc.received[i] = nil
				unprocessed--
			}
		}

		if next == nil {
			// If the number of requested blocks is zero, that means that
			// the peer has sent us a block that is not connected to anything
			// that we know about yet. It's probably the latest block.
			if len(bc.requested) == 0 {
				return ErrNoKnownPrevious
			}

			break
		}

		h := next.Header.BlockHash()
		best = &h

		if ferr := f(next); ferr != nil {
			err = ferr
			break
		}
	}

	// The list hasn't changed, so we don't need to do anything.
	if unprocessed == len(bc.received) {
		return
	}

	// The list is empty, so we can reset it.
	if unprocessed == 0 {
		bc.received = nil
		return
	}

	// Get rid of all nil elements in the list.
	i := 0
	received := bc.received
	bc.received = make([]*wire.MsgMerkleBlock, unprocessed)
	for _, r := range received {
		if r != nil {
			bc.received[i] = r
			i++
		}
	}

	return
}

// newBlockRequests creates a new blockRequests object.
func newBlockRequests() *blockRequests {
	bq := blockRequests{}
	bq.reset()
	return &bq
}
