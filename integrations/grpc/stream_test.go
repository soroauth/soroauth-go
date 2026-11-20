package grpc

import (
	"context"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"

	soroauthv1 "github.com/soroauth/soroauth-go/integrations/grpc/gen"
)

// vectorNamed returns one golden vector by name.
func vectorNamed(t *testing.T, name string) vector {
	t.Helper()
	for _, v := range loadVectors(t) {
		if v.Name == name {
			return v
		}
	}
	t.Fatalf("vector %q not found", name)
	return vector{}
}

// drainStream reads every response until the server closes the stream.
func drainStream(t *testing.T, stream soroauthv1.SoroauthService_SignStreamClient) []*soroauthv1.SignStreamResponse {
	t.Helper()
	var responses []*soroauthv1.SignStreamResponse
	for {
		response, err := stream.Recv()
		if err == io.EOF {
			return responses
		}
		if err != nil {
			t.Fatalf("receiving a stream result: %v", err)
		}
		responses = append(responses, response)
	}
}

func TestSignStreamContinuesPastAnItemFailure(t *testing.T) {
	vectors := loadVectors(t)
	client := serve(t, keySet(t, vectors))

	v := vectorNamed(t, "v2_single_testnet")
	if len(v.Steps) == 0 {
		t.Fatal("vector has no steps")
	}
	signer := signerForStep(t, v.Steps[0])
	target := stepTarget(v.Steps[0], signer)

	stream, err := client.SignStream(context.Background())
	if err != nil {
		t.Fatalf("opening the stream: %v", err)
	}

	const good = 4
	for i := 1; i <= good; i++ {
		if err := stream.Send(&soroauthv1.SignStreamRequest{
			Sequence: uint64(i),
			Request: &soroauthv1.SignRequest{
				Entry:            v.UnsignedEntryXDR,
				ValidUntilLedger: v.ValidUntilLedger,
				Network:          "testnet",
				Address:          target,
			},
		}); err != nil {
			t.Fatalf("sending item %d: %v", i, err)
		}
	}
	if err := stream.Send(&soroauthv1.SignStreamRequest{
		Sequence: 99,
		Request:  &soroauthv1.SignRequest{Entry: "!!!not-xdr!!!", ValidUntilLedger: v.ValidUntilLedger, Network: "testnet", Address: target},
	}); err != nil {
		t.Fatalf("sending the failing item: %v", err)
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatalf("closing the send side: %v", err)
	}

	responses := drainStream(t, stream)
	if len(responses) != good+1 {
		t.Fatalf("got %d results, want %d", len(responses), good+1)
	}

	seen := make(map[uint64]bool, len(responses))
	failures := 0
	for _, response := range responses {
		if seen[response.GetSequence()] {
			t.Errorf("sequence %d was answered twice", response.GetSequence())
		}
		seen[response.GetSequence()] = true
		if response.GetSequence() == 99 {
			if response.GetError() == "" {
				t.Error("the failing item reported no error")
			}
			if response.GetSigned() != nil {
				t.Error("the failing item also carried a signed entry")
			}
			failures++
			continue
		}
		if response.GetSigned() == nil || response.GetSigned().GetSignedEntry() == "" {
			t.Errorf("sequence %d did not return a signed entry: %v", response.GetSequence(), response.GetError())
		}
	}
	if failures != 1 {
		t.Fatalf("got %d item failures, want 1", failures)
	}
}

func TestSignStreamEchoesSequenceAndBoundsConcurrency(t *testing.T) {
	v := vectorNamed(t, "v2_single_testnet")
	signer := signerForStep(t, v.Steps[0])

	var inFlight atomic.Int32
	var peak atomic.Int32
	slow := soroauth.SignerFunc(signer.Address(), func(ctx context.Context, preimage xdr.HashIdPreimage, payload [32]byte) (xdr.ScVal, error) {
		current := inFlight.Add(1)
		for {
			observed := peak.Load()
			if current <= observed || peak.CompareAndSwap(observed, current) {
				break
			}
		}
		time.Sleep(2 * time.Millisecond)
		inFlight.Add(-1)
		return signer.Sign(ctx, preimage, payload)
	})

	client := serve(t, map[string]soroauth.Signer{slow.Address(): slow})
	stream, err := client.SignStream(context.Background())
	if err != nil {
		t.Fatalf("opening the stream: %v", err)
	}

	const items = 64
	go func() {
		for i := 0; i < items; i++ {
			_ = stream.Send(&soroauthv1.SignStreamRequest{
				Sequence: uint64(i),
				Request: &soroauthv1.SignRequest{
					Entry:            v.UnsignedEntryXDR,
					ValidUntilLedger: v.ValidUntilLedger,
					Network:          "testnet",
					Address:          signer.Address(),
				},
			})
		}
		_ = stream.CloseSend()
	}()

	responses := drainStream(t, stream)
	if len(responses) != items {
		t.Fatalf("got %d results, want %d", len(responses), items)
	}
	seen := make(map[uint64]bool, items)
	for _, response := range responses {
		seen[response.GetSequence()] = true
	}
	for i := 0; i < items; i++ {
		if !seen[uint64(i)] {
			t.Errorf("sequence %d was not echoed", i)
		}
	}
	if peak.Load() > streamInFlight {
		t.Errorf("peak concurrency = %d, want at most %d", peak.Load(), streamInFlight)
	}
	if peak.Load() < 2 {
		t.Errorf("peak concurrency = %d; the stream did not sign concurrently", peak.Load())
	}
}
