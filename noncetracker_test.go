package soroauth

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
)

func TestInMemoryNonceTrackerReservesEachNonceOnce(t *testing.T) {
	tracker := NewInMemoryNonceTracker()
	ctx := context.Background()
	const address = "GBEXAMPLE"

	if err := tracker.Reserve(ctx, address, 1); err != nil {
		t.Fatalf("first reservation of nonce 1: unexpected error: %v", err)
	}
	if err := tracker.Reserve(ctx, address, 2); err != nil {
		t.Fatalf("reserving a different nonce: unexpected error: %v", err)
	}
}

func TestInMemoryNonceTrackerRejectsARepeatForTheSameAddress(t *testing.T) {
	tracker := NewInMemoryNonceTracker()
	ctx := context.Background()
	const address = "GBEXAMPLE"

	if err := tracker.Reserve(ctx, address, 42); err != nil {
		t.Fatalf("first reservation: unexpected error: %v", err)
	}

	err := tracker.Reserve(ctx, address, 42)
	if err == nil {
		t.Fatal("reserving the same nonce twice for the same address succeeded")
	}
	if !errors.Is(err, ErrNonceAlreadyReserved) {
		t.Errorf("error %q does not match ErrNonceAlreadyReserved", err)
	}
	var typed *NonceAlreadyReservedError
	if !errors.As(err, &typed) {
		t.Fatal("errors.As did not recover a *NonceAlreadyReservedError")
	}
	if typed.Address != address || typed.Nonce != 42 {
		t.Errorf("typed error = %+v, want Address=%q Nonce=42", typed, address)
	}
}

// TestInMemoryNonceTrackerTracksEachAddressIndependently proves the same
// nonce value is fine for two different addresses: the tracker's key is the
// (address, nonce) pair, not the nonce alone.
func TestInMemoryNonceTrackerTracksEachAddressIndependently(t *testing.T) {
	tracker := NewInMemoryNonceTracker()
	ctx := context.Background()

	if err := tracker.Reserve(ctx, "GADDRESS1", 7); err != nil {
		t.Fatalf("reserving nonce 7 for the first address: unexpected error: %v", err)
	}
	if err := tracker.Reserve(ctx, "GADDRESS2", 7); err != nil {
		t.Fatalf("reserving nonce 7 for a different address: unexpected error: %v", err)
	}
}

func TestInMemoryNonceTrackerHonoursContextCancellation(t *testing.T) {
	tracker := NewInMemoryNonceTracker()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := tracker.Reserve(ctx, "GBEXAMPLE", 1)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error %q does not wrap context.Canceled", err)
	}
}

// TestInMemoryNonceTrackerConcurrentReserveIsRace-safe proves Reserve is
// safe under concurrent use: run with -race, this fails on any data race,
// and functionally it proves that among many goroutines racing to reserve
// the same nonce for the same address, exactly one wins.
func TestInMemoryNonceTrackerConcurrentReserveIsRaceSafe(t *testing.T) {
	tracker := NewInMemoryNonceTracker()
	ctx := context.Background()
	const address = "GBEXAMPLE"
	const contenders = 200

	var wg sync.WaitGroup
	var successes int32
	var mu sync.Mutex // guards successes; kept separate from the tracker's own lock

	for i := 0; i < contenders; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := tracker.Reserve(ctx, address, 999); err == nil {
				mu.Lock()
				successes++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if successes != 1 {
		t.Errorf("%d goroutines succeeded reserving the same nonce, want exactly 1", successes)
	}
}

// TestInMemoryNonceTrackerConcurrentDistinctNoncesAllSucceed is the other
// half: goroutines reserving distinct nonces concurrently for the same
// address must all succeed, with none lost to the locking.
func TestInMemoryNonceTrackerConcurrentDistinctNoncesAllSucceed(t *testing.T) {
	tracker := NewInMemoryNonceTracker()
	ctx := context.Background()
	const address = "GBEXAMPLE"
	const count = 200

	var wg sync.WaitGroup
	errs := make([]error, count)
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(nonce int64) {
			defer wg.Done()
			errs[nonce] = tracker.Reserve(ctx, address, nonce)
		}(int64(i))
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("nonce %d: unexpected error: %v", i, err)
		}
	}
}

// ExampleNewInMemoryNonceTracker shows the collision-avoidance pattern: try
// to reserve a freshly generated nonce, and pick another on
// ErrNonceAlreadyReserved.
func ExampleNewInMemoryNonceTracker() {
	tracker := NewInMemoryNonceTracker()
	ctx := context.Background()
	const address = "GBEXAMPLE"

	if err := tracker.Reserve(ctx, address, 1); err != nil {
		fmt.Println("error:", err)
		return
	}

	// A second reservation of the same nonce for the same address is
	// refused; a caller generating nonces would retry with a fresh one.
	err := tracker.Reserve(ctx, address, 1)
	fmt.Println("collision detected:", errors.Is(err, ErrNonceAlreadyReserved))
	// Output:
	// collision detected: true
}
