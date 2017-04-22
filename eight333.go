package spvwallet

import (
	"fmt"
	"sync"
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

type SPVManager struct {
	mutex *sync.RWMutex

	running  bool
	stopChan chan int

	Blockchain  *Blockchain
	TxStore     *TxStore
	PeerManager *PeerManager

	fPositives    chan *peer.Peer
	fpAccumulator map[int32]uint32
	blockQueue    chan chainhash.Hash
	toDownload    map[chainhash.Hash]int32

	requests blockRequests

	// maxFilterNewMatches is the maximum number of matches that
	// to a filter which we have received before we recreate and load
	// a new filter.
	maxFilterNewMatches uint32
}

func NewSPVManager(tx *TxStore, b *Blockchain, pm *PeerManager, config *Config) *SPVManager {
	maxFilterNewMatches := config.MaxFilterNewMatches
	if maxFilterNewMatches == 0 {
		maxFilterNewMatches = DefaultMaxFilterNewMatches
	}
	spv := &SPVManager{
		fPositives:          make(chan *peer.Peer),
		fpAccumulator:       make(map[int32]uint32),
		blockQueue:          make(chan chainhash.Hash, 32),
		toDownload:          make(map[chainhash.Hash]int32),
		mutex:               new(sync.RWMutex),
		Blockchain:          b,
		TxStore:             tx,
		PeerManager:         pm,
		maxFilterNewMatches: maxFilterNewMatches,
	}

	spv.requests.reset()
	return spv
}

func (w *SPVManager) Start() {
	w.running = true
	w.PeerManager.Start()
	go w.fPositiveHandler(w.stopChan, w.maxFilterNewMatches)
}

func (w *SPVManager) Close() {
	if w.running {
		log.Info("Disconnecting from peers and shutting down")
		w.PeerManager.Stop()
		w.Blockchain.Close()
		close(w.stopChan)
		w.running = false
	}
}

func (w *SPVManager) startChainDownload(p *peer.Peer) {
	defer func() {
		if r := recover(); r != nil {
			log.Error("Unhandled error in startChainDownload", r)
		}
	}()
	w.mutex.Lock()
	defer w.mutex.Unlock()
	if w.Blockchain.ChainState() == SYNCING {
		height, _ := w.Blockchain.db.Height()
		if height >= uint32(p.LastBlock()) {
			moar := w.PeerManager.CheckForMoreBlocks(height)
			if !moar {
				log.Info("Chain download complete")
				w.Blockchain.SetChainState(WAITING)
				w.Rebroadcast()
			}
			return
		}
		gBlocks := wire.NewMsgGetBlocks(maxHash)
		hashes := w.Blockchain.GetBlockLocatorHashes()
		gBlocks.BlockLocatorHashes = hashes
		p.QueueMessage(gBlocks, nil)
	}
}

func (w *SPVManager) reset() {
	w.requests.reset()

	// Select a new download peer.
	w.PeerManager.selectNewDownloadPeer()
}

func (w *SPVManager) onMerkleBlock(p *peer.Peer, m *wire.MsgMerkleBlock) {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	var err error
	// If this is the sync peer, there are potentially
	if w.Blockchain.ChainState() == SYNCING && w.PeerManager.DownloadPeer() != nil && w.PeerManager.DownloadPeer().ID() == p.ID() {
		best, _ := w.Blockchain.db.GetBestHeader()
		hash := best.Header.BlockHash()

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

func (w *SPVManager) processBlock(p *peer.Peer, m *wire.MsgMerkleBlock) error {
	txids, err := checkMBlock(m)
	if err != nil {
		p.Disconnect()
		return fmt.Errorf("Peer%d sent an invalid MerkleBlock", p.ID())
	}
	newBlock, reorg, height, err := w.Blockchain.CommitHeader(m.Header)
	if err != nil {
		return err
	}
	if !newBlock {
		return nil
	}

	// We hit a reorg. Rollback the transactions and resync from the reorg point.
	if reorg != nil {
		err := w.TxStore.processReorg(reorg.Height)
		if err != nil {
			log.Error(err)
		}
		if w.Blockchain.state != SYNCING {
			w.Blockchain.SetChainState(SYNCING)
			w.Blockchain.db.Put(*reorg, true)
			go w.startChainDownload(p)
			return nil
		}
	}

	for _, txid := range txids {
		w.PeerManager.QueueTxForDownload(p, *txid, int32(height))
	}

	log.Debugf("Received Merkle Block %s at height %d\n", m.Header.BlockHash().String(), height)
	if w.Blockchain.ChainState() == WAITING {
		txns, err := w.TxStore.Txns().GetAll(false)
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
				err = w.TxStore.markAsDead(*h)
				if err != nil {
					log.Error(err)
					continue
				}
			}
		}
	}

	return nil
}

func (w *SPVManager) onTx(p *peer.Peer, m *wire.MsgTx) {
	w.mutex.Lock()
	height, err := w.PeerManager.DequeueTx(p, m.TxHash())
	if err != nil {
		w.mutex.Unlock()
		return
	}
	w.mutex.Unlock()

	hits, err := w.TxStore.Ingest(m, height)
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

func (w *SPVManager) onInv(p *peer.Peer, m *wire.MsgInv) {
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
				if w.Blockchain.ChainState() == SYNCING && w.PeerManager.DownloadPeer() != nil && w.PeerManager.DownloadPeer().ID() == p.ID() {
					w.requests.add(&inv.Hash)
				}
			case wire.InvTypeTx:
				w.PeerManager.QueueTxForDownload(p, inv.Hash, 0)
				gData := wire.NewMsgGetData()
				gData.AddInvVect(inv)
				p.QueueMessage(gData, nil)
			default:
				continue
			}

		}
	}()
}

func (w *SPVManager) onReject(p *peer.Peer, m *wire.MsgReject) {
	log.Warningf("Received reject message from peer %d: Code: %s, Hash %s, Reason: %s", int(p.ID()), m.Code.String(), m.Hash.String(), m.Reason)
}

func (w *SPVManager) onGetData(p *peer.Peer, m *wire.MsgGetData) {
	log.Debugf("Received getdata request from Peer%d\n", p.ID())
	var sent int32
	for _, thing := range m.InvList {
		if thing.Type == wire.InvTypeTx {
			tx, _, err := w.TxStore.Txns().Get(thing.Hash)
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

func (w *SPVManager) fPositiveHandler(quit chan int, maxFilterNewMatches uint32) {
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

func (w *SPVManager) updateFilterAndSend(p *peer.Peer) {
	filt, err := w.TxStore.GimmeFilter()
	if err != nil {
		log.Errorf("Error creating filter: %s\n", err.Error())
		return
	}
	// send filter
	p.QueueMessage(filt.MsgFilterLoad(), nil)
	log.Debugf("Sent filter to Peer%d\n", p.ID())
}

func (w *SPVManager) Rebroadcast() {
	// get all unconfirmed txs
	invMsg, err := w.TxStore.GetPendingInv()
	if err != nil {
		log.Errorf("Rebroadcast error: %s", err.Error())
	}
	if len(invMsg.InvList) == 0 { // nothing to broadcast, so don't
		return
	}
	for _, peer := range w.PeerManager.ReadyPeers() {
		peer.QueueMessage(invMsg, nil)
	}
}
