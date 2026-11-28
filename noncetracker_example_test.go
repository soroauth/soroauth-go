package soroauth_test

import (
	"context"
	"errors"
	"fmt"

	"github.com/soroauth/soroauth-go"
)

const nonceTrackerExampleAddress = "GASI5PH5KDJFVFU4XGLLRGRNA426GVNZQCLA6PENWMAJRJ4JC3GC4CQ5"

// ExampleNewInMemoryNonceTracker reserves a nonce before signing. Each
// in-memory tracker keeps process-local reservations. Use a NonceTracker
// backed by a shared durable store to retain reservations across restarts
// and share them among signing processes.
func ExampleNewInMemoryNonceTracker() {
	tracker := soroauth.NewInMemoryNonceTracker()
	ctx := context.Background()
	const nonce = 42

	if err := tracker.Reserve(ctx, nonceTrackerExampleAddress, nonce); err != nil {
		panic(err)
	}
	fmt.Println("first reservation accepted")

	err := tracker.Reserve(ctx, nonceTrackerExampleAddress, nonce)
	fmt.Println("repeat refused:", errors.Is(err, soroauth.ErrNonceAlreadyReserved))

	// Output:
	// first reservation accepted
	// repeat refused: true
}
