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

package ethash

import (
	"bytes"
	"encoding/binary"
	"github.com/ethereum/go-ethereum/core/types"
	"testing"

	"github.com/ethereum/go-ethereum/common/hexutil"
)

// prepare converts an hmhash cache or dataset from a byte stream into the internal
// int representation. All hmhash methods work with ints to avoid constant byte to
// int conversions as well as to handle both little and big endian systems.
func prepare(dest []uint32, src []byte) {
	for i := 0; i < len(dest); i++ {
		dest[i] = binary.LittleEndian.Uint32(src[i*4:])
	}
}

// Tests whether the hashimoto lookup works for both light as well as the full
// datasets.
func TestHashimoto(t *testing.T) {
	// Create a block to verify
	hash := hexutil.MustDecode("0xc9149cc0386e689d789a1c2f3d5d169a61a6218ed30e74414dc736e442ef3d1f")
	nonce := uint64(0)

	wantResult := hexutil.MustDecode("0xd3539235ee2e6f8db665c0a72169f55b7f6c605712330b778ec3944f0eb5a557")

	result := hashimotoLight(hash, types.EncodeNonce(nonce).Hash())
	if !bytes.Equal(result, wantResult) {
		t.Errorf("light hashimoto result mismatch: have %x, want %x", result, wantResult)
	}
	result = hashimotoFull(hash, types.EncodeNonce(nonce).Hash())
	if !bytes.Equal(result, wantResult) {
		t.Errorf("full hashimoto result mismatch: have %x, want %x", result, wantResult)
	}
}

// Benchmarks the light verification performance.
func BenchmarkHashimotoLight(b *testing.B) {
	hash := hexutil.MustDecode("0xc9149cc0386e689d789a1c2f3d5d169a61a6218ed30e74414dc736e442ef3d1f")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hashimotoLight(hash, types.EncodeNonce(0).Hash())
	}
}

// Benchmarks the full (small) verification performance.
func BenchmarkHashimotoFullSmall(b *testing.B) {
	hash := hexutil.MustDecode("0xc9149cc0386e689d789a1c2f3d5d169a61a6218ed30e74414dc736e442ef3d1f")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hashimotoFull(hash, types.EncodeNonce(0).Hash())
	}
}
