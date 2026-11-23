// Command trace-transfer runs a native-XLM SAC transfer on Stellar testnet
// through rpcflow.SignAndSubmit and prints the whole flow as one
// OpenTelemetry trace: record pass, signing, enforcing pass, submission and
// polling.
//
// Every account is generated at runtime and funded by friendbot. No key is
// read from the environment, written to disk, or printed; only addresses are.
// The program refuses to run against any network but testnet.
//
// Configuration (all optional):
//
//	SOROAUTH_RPC_URL        RPC endpoint (default https://soroban-testnet.stellar.org)
//	SOROAUTH_FRIENDBOT_URL  friendbot (default: the one the RPC advertises,
//	                        else https://friendbot.stellar.org/)
//
// Flags:
//
//	-json   also print every span as JSON via the stdouttrace exporter
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/stellar/go-stellar-sdk/clients/rpcclient"
	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/network"
	rpc "github.com/stellar/go-stellar-sdk/protocols/rpc"
	"github.com/stellar/go-stellar-sdk/txnbuild"
	"github.com/stellar/go-stellar-sdk/xdr"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/soroauth/soroauth-go"
	otelexample "github.com/soroauth/soroauth-go/examples/opentelemetry"
	"github.com/soroauth/soroauth-go/rpcflow"
)

const (
	defaultRPCURL       = "https://soroban-testnet.stellar.org"
	defaultFriendbotURL = "https://friendbot.stellar.org/"
	// transferStroops is 1 XLM.
	transferStroops = 10_000_000
)

func main() {
	jsonOut := flag.Bool("json", false, "also print every span as JSON via the stdouttrace exporter")
	flag.Parse()
	if err := run(context.Background(), os.Stdout, *jsonOut); err != nil {
		fmt.Fprintf(os.Stderr, "trace-transfer: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, out io.Writer, jsonOut bool) error {
	rpcURL := envOr("SOROAUTH_RPC_URL", defaultRPCURL)
	client := rpcclient.NewClient(rpcURL, nil)
	defer func() { _ = client.Close() }()

	// Verify the endpoint with a live call before relying on it, and refuse
	// anything that is not testnet: this program funds and spends from fresh
	// accounts and has no business on a network where XLM is real.
	setupCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	net, err := client.GetNetwork(setupCtx)
	if err != nil {
		return fmt.Errorf("the RPC at %s did not answer getNetwork: %w", rpcURL, err)
	}
	if net.Passphrase != network.TestNetworkPassphrase {
		return fmt.Errorf("the RPC at %s is on %q; this example runs on testnet only", rpcURL, net.Passphrase)
	}
	latest, err := client.GetLatestLedger(setupCtx)
	if err != nil {
		return fmt.Errorf("the RPC at %s did not answer getLatestLedger: %w", rpcURL, err)
	}
	friendbot := envOr("SOROAUTH_FRIENDBOT_URL", net.FriendbotURL)
	if friendbot == "" {
		friendbot = defaultFriendbotURL
	}
	fmt.Fprintf(out, "rpc:       %s (protocol %d, ledger %d)\n", rpcURL, latest.ProtocolVersion, latest.Sequence)

	// Three accounts, generated here and never persisted. The payer and the
	// entry signer are different accounts on purpose: that is what makes the
	// transfer need an address credential, and so both simulation passes.
	payer, from, to, err := newAccounts(ctx, friendbot)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "payer:     %s\nfrom:      %s\nto:        %s\n", payer.Address(), from.Address(), to.Address())

	source, err := client.LoadAccount(setupCtx, payer.Address())
	if err != nil {
		return fmt.Errorf("loading the payer account: %w", err)
	}
	op, err := transferOp(payer.Address(), from.Address(), to.Address())
	if err != nil {
		return err
	}

	recorder := tracetest.NewSpanRecorder()
	opts := []sdktrace.TracerProviderOption{
		sdktrace.WithSpanProcessor(recorder),
		sdktrace.WithResource(resource.NewSchemaless(
			attribute.String("service.name", "soroauth-trace-transfer"),
		)),
	}
	if jsonOut {
		exporter, err := stdouttrace.New(stdouttrace.WithWriter(out), stdouttrace.WithPrettyPrint())
		if err != nil {
			return fmt.Errorf("creating the stdout exporter: %w", err)
		}
		opts = append(opts, sdktrace.WithSyncer(exporter))
	}
	provider := sdktrace.NewTracerProvider(opts...)
	defer func() { _ = provider.Shutdown(context.Background()) }()

	flowCtx, flowCancel := context.WithTimeout(ctx, 2*time.Minute)
	defer flowCancel()
	sub, err := otelexample.SignAndSubmit(flowCtx, provider.Tracer("github.com/soroauth/soroauth-go/examples/opentelemetry"), rpcflow.Params{
		Source:            source,
		Operation:         op,
		Signers:           []soroauth.Signer{soroauth.NewEd25519Signer(from)},
		EnvelopeSigners:   []*keypair.Full{payer},
		NetworkPassphrase: net.Passphrase,
		Client:            client,
	})

	fmt.Fprintf(out, "\n%s", otelexample.RenderTree(recorder.Ended()))
	if err != nil {
		return fmt.Errorf("the flow did not complete: %w", err)
	}
	fmt.Fprintf(out, "\nstatus:    %s\nledger:    %d\narm:       %s\nexplorer:  https://stellar.expert/explorer/testnet/tx/%s\n",
		sub.Status, sub.Ledger, sub.Arm, sub.Hash)
	if sub.Status != rpc.TransactionStatusSuccess {
		return fmt.Errorf("the transaction did not succeed (status %s): %s", sub.Status, sub.RawError)
	}
	return nil
}

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

// newAccounts generates and funds the payer, the sender and the recipient. The
// recipient must exist too: a native transfer to an unfunded G-account fails.
func newAccounts(ctx context.Context, friendbot string) (payer, from, to *keypair.Full, err error) {
	keys := make([]*keypair.Full, 3)
	for i := range keys {
		if keys[i], err = keypair.Random(); err != nil {
			return nil, nil, nil, fmt.Errorf("generating a keypair: %w", err)
		}
		if err := fund(ctx, friendbot, keys[i].Address()); err != nil {
			return nil, nil, nil, err
		}
	}
	return keys[0], keys[1], keys[2], nil
}

func fund(ctx context.Context, friendbot, address string) error {
	endpoint, err := url.Parse(friendbot)
	if err != nil {
		return fmt.Errorf("parsing the friendbot URL: %w", err)
	}
	q := endpoint.Query()
	q.Set("addr", address)
	endpoint.RawQuery = q.Encode()

	var lastErr error
	for attempt := 0; attempt < 4; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * 2 * time.Second)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
		if err != nil {
			return fmt.Errorf("building the friendbot request: %w", err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			return nil
		}
		lastErr = fmt.Errorf("friendbot returned %d: %s", resp.StatusCode, body)
	}
	return fmt.Errorf("funding %s: %w", address, lastErr)
}

// transferOp builds transfer(from, to, 1 XLM) against the native SAC, with the
// payer as the operation source, so from's authorization is an address
// credential the payer cannot provide.
func transferOp(payer, from, to string) (txnbuild.InvokeHostFunction, error) {
	contractID, err := xdr.MustNewNativeAsset().ContractID(network.TestNetworkPassphrase)
	if err != nil {
		return txnbuild.InvokeHostFunction{}, fmt.Errorf("deriving the native SAC contract id: %w", err)
	}
	id := xdr.ContractId(contractID)
	fromAddr, err := soroauth.ParseAddress(from)
	if err != nil {
		return txnbuild.InvokeHostFunction{}, err
	}
	toAddr, err := soroauth.ParseAddress(to)
	if err != nil {
		return txnbuild.InvokeHostFunction{}, err
	}
	amount := xdr.Int128Parts{Hi: 0, Lo: xdr.Uint64(transferStroops)}
	return txnbuild.InvokeHostFunction{
		HostFunction: xdr.HostFunction{
			Type: xdr.HostFunctionTypeHostFunctionTypeInvokeContract,
			InvokeContract: &xdr.InvokeContractArgs{
				ContractAddress: xdr.ScAddress{Type: xdr.ScAddressTypeScAddressTypeContract, ContractId: &id},
				FunctionName:    xdr.ScSymbol("transfer"),
				Args: xdr.ScVec{
					{Type: xdr.ScValTypeScvAddress, Address: &fromAddr},
					{Type: xdr.ScValTypeScvAddress, Address: &toAddr},
					{Type: xdr.ScValTypeScvI128, I128: &amount},
				},
			},
		},
		SourceAccount: payer,
	}, nil
}
