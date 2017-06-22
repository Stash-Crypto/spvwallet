package spvwallet

import (
	"fmt"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/peer"
	"github.com/btcsuite/btcd/wire"
)

const DefaultMaxFilterNewMatches = 7

var (
	maxHash              *chainhash.Hash
	MAX_UNCONFIRMED_TIME time.Duration = time.Hour * 24 * 7
)

func init() {
	h, err := chainhash.NewHashFromStr("0000000000000000000000000000000000000000000000000000000000000000")
	if err != nil {
		log.Fatal(err)
	}
	maxHash = h
}

func (w *SPVWallet) startChainDownload(p *peer.Peer) {
	defer func() {
		if r := recover(); r != nil {
			log.Error("Unhandled error in startChainDownload", r)
		}
	}()
	w.mutex.Lock()
	defer w.mutex.Unlock()
	if w.blockchain.ChainState() == SYNCING {
		height, _ := w.blockchain.db.Height()
		if height >= uint32(p.LastBlock()) {
			moar := w.peerManager.CheckForMoreBlocks(height)
			if !moar {
				log.Info("Chain download complete")
				w.blockchain.SetChainState(WAITING)
				w.Rebroadcast()
			}
			return
		}
		gBlocks := wire.NewMsgGetBlocks(maxHash)
		hashes := w.blockchain.GetBlockLocatorHashes()
		gBlocks.BlockLocatorHashes = hashes
		p.QueueMessage(gBlocks, nil)
	}
}

func (w *SPVWallet) reset() {
	w.requests.reset()

	// Select a new download peer.
	w.peerManager.selectNewDownloadPeer()
}

func (w *SPVWallet) onMerkleBlock(p *peer.Peer, m *wire.MsgMerkleBlock) {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	var err error
	// If this is the sync peer, there are potentially
	if w.blockchain.ChainState() == SYNCING && w.peerManager.DownloadPeer() != nil && w.peerManager.DownloadPeer().ID() == p.ID() {
		best, _ := w.blockchain.db.GetBestHeader()
		hash := best.header.BlockHash()

		// We may need to process multiple cached block headers.
		err = w.requests.process(&hash, m, func(m *wire.MsgMerkleBlock) error {
			return w.processBlock(p, m)
		})

		if err == nil {
			// Continue syncing if the request cache is empty.
			if w.requests.empty() {
				go w.startChainDownload(p)
			}

			return
		}

		// If we received a block that we didn't request, find a new
		// sync peer.
		if err == ErrUnrequested {
			w.reset()
			return
		}

		// If there are headers with no known previous header, we continue
		// syncing from the peer but we reset the request cache.
		if err == ErrNoKnownPrevious {
			w.requests.reset()
			return
		}
	} else {
		// If this is not from the sync peer, process the block normally.
		err = w.processBlock(p, m)
	}

	if err != nil {
		log.Error(err)
	}
}

func (w *SPVWallet) processBlock(p *peer.Peer, m *wire.MsgMerkleBlock) error {
	txids, err := checkMBlock(m)
	if err != nil {
		p.Disconnect()
		return fmt.Errorf("Peer%d sent an invalid MerkleBlock", p.ID())
	}
	newBlock, reorg, height, err := w.blockchain.CommitHeader(m.Header)
	if err != nil {
		return err
	}
	if !newBlock {
		return nil
	}

	// We hit a reorg. Rollback the transactions and resync from the reorg point.
	if reorg != nil {
		err := w.txstore.processReorg(reorg.height)
		if err != nil {
			log.Error(err)
		}
		if w.blockchain.state != SYNCING {
			w.blockchain.SetChainState(SYNCING)
			w.blockchain.db.Put(*reorg, true)
			go w.startChainDownload(p)
			return nil
		}
	}

	for _, txid := range txids {
		w.peerManager.QueueTxForDownload(p, *txid, int32(height))
	}

	log.Debugf("Received Merkle Block %s at height %d\n", m.Header.BlockHash().String(), height)
	if w.blockchain.ChainState() == WAITING {
		txns, err := w.txstore.Txns().GetAll(false)
		if err != nil {
			return err
		}
		now := time.Now()
		for i := len(txns) - 1; i >= 0; i-- {
			if now.After(txns[i].Timestamp.Add(MAX_UNCONFIRMED_TIME)) && txns[i].Height == int32(0) {
				log.Noticef("Marking tx as dead %s", txns[i].Txid)
				h, err := chainhash.NewHashFromStr(txns[i].Txid)
				if err != nil {
					log.Error(err)
					continue
				}
				err = w.txstore.markAsDead(*h)
				if err != nil {
					log.Error(err)
					continue
				}
			}
		}
	}

	return nil
}

func (w *SPVWallet) onTx(p *peer.Peer, m *wire.MsgTx) {
	w.mutex.Lock()
	height, err := w.peerManager.DequeueTx(p, m.TxHash())
	if err != nil {
		w.mutex.Unlock()
		return
	}
	w.mutex.Unlock()
	hits, err := w.txstore.Ingest(m, height)
	if err != nil {
		log.Errorf("Error ingesting tx: %s\n", err.Error())
		return
	}
	if hits == 0 {
		log.Debugf("Tx %s from Peer%d had no hits, filter false positive.", m.TxHash().String(), p.ID())
		w.fPositives <- p
		return
	}
	w.updateFilterAndSend(p)
	log.Infof("Tx %s from Peer%d ingested at height %d", m.TxHash().String(), p.ID(), height)
}

func (w *SPVWallet) onInv(p *peer.Peer, m *wire.MsgInv) {
	go func() {
		defer func() {
			w.mutex.Unlock()
			if err := recover(); err != nil {
				log.Error(err)
			}
		}()
		w.mutex.Lock()
		for _, inv := range m.InvList {
			switch inv.Type {
			case wire.InvTypeBlock:
				// Kind of lame to send separate getData messages but this allows us
				// to take advantage of the timeout on the upper layer. Otherwise we
				// need separate timeout handling.
				inv.Type = wire.InvTypeFilteredBlock
				gData := wire.NewMsgGetData()
				gData.AddInvVect(inv)
				p.QueueMessage(gData, nil)
				if w.blockchain.ChainState() == SYNCING && w.peerManager.DownloadPeer() != nil && w.peerManager.DownloadPeer().ID() == p.ID() {
					w.requests.add(&inv.Hash)
				}
			case wire.InvTypeTx:
				w.peerManager.QueueTxForDownload(p, inv.Hash, 0)
				gData := wire.NewMsgGetData()
				gData.AddInvVect(inv)
				p.QueueMessage(gData, nil)
			default:
				continue
			}

		}
	}()
}

func (w *SPVWallet) onReject(p *peer.Peer, m *wire.MsgReject) {
	log.Warningf("Received reject message from peer %d: Code: %s, Hash %s, Reason: %s", int(p.ID()), m.Code.String(), m.Hash.String(), m.Reason)
}

func (w *SPVWallet) onGetData(p *peer.Peer, m *wire.MsgGetData) {
	log.Debugf("Received getdata request from Peer%d\n", p.ID())
	var sent int32
	for _, thing := range m.InvList {
		if thing.Type == wire.InvTypeTx {
			tx, _, err := w.txstore.Txns().Get(thing.Hash)
			if err != nil {
				log.Errorf("Error getting tx %s: %s", thing.Hash.String(), err.Error())
				continue
			}
			p.QueueMessageWithEncoding(tx, nil, wire.WitnessEncoding)
			sent++
			continue
		}
		// didn't match, so it's not something we're responding to
		log.Debugf("We only respond to tx requests, ignoring")

	}
	log.Debugf("Sent %d of %d requested items to Peer%d", sent, len(m.InvList), p.ID())
}

func (w *SPVWallet) fPositiveHandler(quit chan int, maxFilterNewMatches uint32) {

exit:
	for {
		select {
		case peer := <-w.fPositives:
			w.mutex.RLock()
			falsePostives, _ := w.fpAccumulator[peer.ID()]
			w.mutex.RUnlock()
			falsePostives++
			if falsePostives > maxFilterNewMatches {
				w.updateFilterAndSend(peer)
				log.Debugf("Reset %d false positives for Peer%d\n", falsePostives, peer.ID())
				// reset accumulator
				falsePostives = 0
			}
			w.mutex.Lock()
			w.fpAccumulator[peer.ID()] = falsePostives
			w.mutex.Unlock()
		case <-quit:
			break exit
		}
	}
}

func (w *SPVWallet) updateFilterAndSend(p *peer.Peer) {
	filt, err := w.txstore.GimmeFilter()
	if err != nil {
		log.Errorf("Error creating filter: %s\n", err.Error())
		return
	}
	// send filter
	p.QueueMessage(filt.MsgFilterLoad(), nil)
	log.Debugf("Sent filter to Peer%d\n", p.ID())
}

func (w *SPVWallet) Rebroadcast() {
	// get all unconfirmed txs
	invMsg, err := w.txstore.GetPendingInv()
	if err != nil {
		log.Errorf("Rebroadcast error: %s", err.Error())
	}
	if len(invMsg.InvList) == 0 { // nothing to broadcast, so don't
		return
	}
	for _, peer := range w.peerManager.ReadyPeers() {
		peer.QueueMessage(invMsg, nil)
	}
}
