
package transport

import (
	"runtime"
	"sync"
	"testing"
)

func TestBufferPoolAllocation(t *testing.T) {
	b := allocateBuffer()
	if b == nil {
		t.Fatal("allocateBuffer() returned nil")
	}

	// On a new buffer, PacketBytes should be empty because n is 0.
	if len(b.PacketBytes()) != 0 {
		t.Errorf("Expected PacketBytes to be empty for a new buffer, but got length %d", len(b.PacketBytes()))
	}
}

func TestBufferPoolReuse(t *testing.T) {
	// Put one item into the pool to ensure there's something to Get.
	releaseBuffer(allocateBuffer())

	// The AllocsPerRun function reports the number of allocations per iteration.
	// We expect that allocating and releasing a buffer from the pool requires zero new allocations.
	allocs := testing.AllocsPerRun(100, func() {
		b := allocateBuffer()
		releaseBuffer(b)
	})

	if allocs > 0 {
		t.Errorf("expected 0 allocations from reusing buffers, got %f", allocs)
	}
}

func TestBufferPoolConcurrency(t *testing.T) {
	// Allow the test to use multiple CPU cores to increase chance of race conditions
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(4))

	var wg sync.WaitGroup
	numGoroutines := 100
	numAllocationsPerG := 50

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buffers := make([]*PacketBuf, numAllocationsPerG)
			for j := 0; j < numAllocationsPerG; j++ {
				buffers[j] = allocateBuffer()
				if buffers[j] == nil {
					t.Error("allocateBuffer() returned nil during concurrent access")
				}
			}
			for j := 0; j < numAllocationsPerG; j++ {
				releaseBuffer(buffers[j])
			}
		}()
	}

	wg.Wait()
}
