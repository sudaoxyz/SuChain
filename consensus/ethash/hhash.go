// Copyright 2017 The go-ethereum Authors
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

// Package hmhash implements the hmhash proof-of-work consensus engine.
package ethash

import (
	"errors"
	"math/big"
	"math/rand"
	"sync"
	"time"
	"unsafe"

	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/ethereum/go-ethereum/rpc"
)

var ErrInvalidDumpMagic = errors.New("invalid dump magic")

var (
	// two256 is a big integer representing 2^256
	two256 = new(big.Int).Exp(big.NewInt(2), big.NewInt(256), big.NewInt(0))

	// sharedHmhash is a full instance that can be shared between multiple users.
	sharedHmhash *Hmhash

	// algorithmRevision is the data structure version used for file naming.
	algorithmRevision = 23

	// dumpMagic is a dataset dump header to sanity check a data dump.
	dumpMagic = []uint32{0xbaddcafe, 0xfee1dead}
)

func init() {
	sharedConfig := Config{
		PowMode: ModeNormal,
	}
	sharedHmhash = New(sharedConfig, nil, false)
}

// isLittleEndian returns whether the local system is running in little or big
// endian byte order.
func isLittleEndian() bool {
	n := uint32(0x01020304)
	return *(*byte)(unsafe.Pointer(&n)) == 0x04
}

// Mode defines the type and amount of PoW verification an hmhash engine makes.
type Mode uint

const (
	ModeNormal Mode = iota
	ModeShared
	ModeTest
	ModeFake
	ModeFullFake
)

// Config are the configuration parameters of the hmhash.
type Config struct {
	PowMode Mode

	// When set, notifications sent by the remote sealer will
	// be block header JSON objects instead of work package arrays.
	NotifyFull bool

	Log log.Logger `toml:"-"`
}

// Hmhash is a consensus engine based on proof-of-work implementing the hmhash
// algorithm.
type Hmhash struct {
	config Config

	// Mining related fields
	rand     *rand.Rand    // Properly seeded random source for nonces
	threads  int           // Number of threads to mine on if mining
	update   chan struct{} // Notification channel to update mining parameters
	hashrate metrics.Meter // Meter tracking the average hashrate
	remote   *remoteSealer

	// The fields below are hooks for testing
	shared    *Hmhash       // Shared PoW verifier to avoid cache regeneration
	fakeFail  uint64        // Block number which fails PoW check even in fake mode
	fakeDelay time.Duration // Time delay to sleep for before returning from verify

	lock      sync.Mutex // Ensures thread safety for the in-memory caches and mining fields
	closeOnce sync.Once  // Ensures exit channel will not be closed twice.
}

// New creates a full sized hmhash PoW scheme and starts a background thread for
// remote mining, also optionally notifying a batch of remote services of new work
// packages.
func New(config Config, notify []string, noverify bool) *Hmhash {
	if config.Log == nil {
		config.Log = log.Root()
	}
	hmhash := &Hmhash{
		config:   config,
		update:   make(chan struct{}),
		hashrate: metrics.NewMeterForced(),
	}
	if config.PowMode == ModeShared {
		hmhash.shared = sharedHmhash
	}
	hmhash.remote = startRemoteSealer(hmhash, notify, noverify)
	return hmhash
}

// NewTester creates a small sized hmhash PoW scheme useful only for testing
// purposes.
func NewTester(notify []string, noverify bool) *Hmhash {
	return New(Config{PowMode: ModeTest}, notify, noverify)
}

// NewFaker creates a hmhash consensus engine with a fake PoW scheme that accepts
// all blocks' seal as valid, though they still have to conform to the Ethereum
// consensus rules.
func NewFaker() *Hmhash {
	return &Hmhash{
		config: Config{
			PowMode: ModeFake,
			Log:     log.Root(),
		},
	}
}

// NewFakeFailer creates a hmhash consensus engine with a fake PoW scheme that
// accepts all blocks as valid apart from the single one specified, though they
// still have to conform to the Ethereum consensus rules.
func NewFakeFailer(fail uint64) *Hmhash {
	return &Hmhash{
		config: Config{
			PowMode: ModeFake,
			Log:     log.Root(),
		},
		fakeFail: fail,
	}
}

// NewFakeDelayer creates a hmhash consensus engine with a fake PoW scheme that
// accepts all blocks as valid, but delays verifications by some time, though
// they still have to conform to the Ethereum consensus rules.
func NewFakeDelayer(delay time.Duration) *Hmhash {
	return &Hmhash{
		config: Config{
			PowMode: ModeFake,
			Log:     log.Root(),
		},
		fakeDelay: delay,
	}
}

// NewFullFaker creates an hmhash consensus engine with a full fake scheme that
// accepts all blocks as valid, without checking any consensus rules whatsoever.
func NewFullFaker() *Hmhash {
	return &Hmhash{
		config: Config{
			PowMode: ModeFullFake,
			Log:     log.Root(),
		},
	}
}

// NewShared creates a full sized hmhash PoW shared between all requesters running
// in the same process.
func NewShared() *Hmhash {
	return &Hmhash{shared: sharedHmhash}
}

// Close closes the exit channel to notify all backend threads exiting.
func (hmhash *Hmhash) Close() error {
	return hmhash.StopRemoteSealer()
}

// StopRemoteSealer stops the remote sealer
func (hmhash *Hmhash) StopRemoteSealer() error {
	hmhash.closeOnce.Do(func() {
		// Short circuit if the exit channel is not allocated.
		if hmhash.remote == nil {
			return
		}
		close(hmhash.remote.requestExit)
		<-hmhash.remote.exitCh
	})
	return nil
}

// Threads returns the number of mining threads currently enabled. This doesn't
// necessarily mean that mining is running!
func (hmhash *Hmhash) Threads() int {
	hmhash.lock.Lock()
	defer hmhash.lock.Unlock()

	return hmhash.threads
}

// SetThreads updates the number of mining threads currently enabled. Calling
// this method does not start mining, only sets the thread count. If zero is
// specified, the miner will use all cores of the machine. Setting a thread
// count below zero is allowed and will cause the miner to idle, without any
// work being done.
func (hmhash *Hmhash) SetThreads(threads int) {
	hmhash.lock.Lock()
	defer hmhash.lock.Unlock()

	// If we're running a shared PoW, set the thread count on that instead
	if hmhash.shared != nil {
		hmhash.shared.SetThreads(threads)
		return
	}
	// Update the threads and ping any running seal to pull in any changes
	hmhash.threads = threads
	select {
	case hmhash.update <- struct{}{}:
	default:
	}
}

// Hashrate implements PoW, returning the measured rate of the search invocations
// per second over the last minute.
// Note the returned hashrate includes local hashrate, but also includes the total
// hashrate of all remote miner.
func (hmhash *Hmhash) Hashrate() float64 {
	// Short circuit if we are run the hmhash in normal/test mode.
	if hmhash.config.PowMode != ModeNormal && hmhash.config.PowMode != ModeTest {
		return hmhash.hashrate.Rate1()
	}
	var res = make(chan uint64, 1)

	select {
	case hmhash.remote.fetchRateCh <- res:
	case <-hmhash.remote.exitCh:
		// Return local hashrate only if hmhash is stopped.
		return hmhash.hashrate.Rate1()
	}

	// Gather total submitted hash rate of remote sealers.
	return hmhash.hashrate.Rate1() + float64(<-res)
}

// APIs implements consensus.Engine, returning the user facing RPC APIs.
func (hmhash *Hmhash) APIs(chain consensus.ChainHeaderReader) []rpc.API {
	// In order to ensure backward compatibility, we exposes hmhash RPC APIs
	// to both eth and hmhash namespaces.
	return []rpc.API{
		{
			Namespace: "eth",
			Service:   &API{hmhash},
		},
		{
			Namespace: "hmhash",
			Service:   &API{hmhash},
		},
	}
}

// SeedHash is the seed to use for generating a verification cache and the mining
// dataset.
func SeedHash(block uint64) []byte {
	return seedHash(block)
}
