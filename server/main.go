// Command soroauth-server exposes soroauth's offline verification over HTTP,
// for wallets and custody systems that want a pre-submission check without
// embedding Go.
//
// It is stateless and holds no entry secrets: verification rebuilds the signing
// payload from the entry itself and checks the signatures against it, which
// needs public data only. There is no field that accepts a secret, nothing is
// stored, and request bodies are never logged.
//
// The service is hardened for untrusted exposure rather than only for a trusted
// network: request bodies are size-limited, every server timeout is set, the
// number of in-flight verification requests is bounded, and a bearer-token
// authentication check can be configured. It fails closed: a non-loopback bind
// without AUTH_TOKEN refuses to start rather than accepting entries from anyone
// who can reach it. The threat model this makes it fit for is stated in
// docs/verification-service.md; the endpoint contract is server/openapi.yaml.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Version is set at build time via -ldflags.
var Version = "dev"

// Defaults for every configurable bound. They are documented in
// docs/verification-service.md, which is the contract an operator reads.
const (
	// defaultAddr binds loopback so the zero-configuration default is not
	// reachable from another host; exposing the service is a deliberate ADDR.
	defaultAddr = "127.0.0.1:8080"
	// defaultMetricsAddr keeps the exposition on loopback too: an operator
	// decides deliberately to expose it, rather than discovering that a deploy
	// exposed it along with the API.
	defaultMetricsAddr       = "127.0.0.1:9090"
	defaultReadTimeout       = 5 * time.Second
	defaultReadHeaderTimeout = 5 * time.Second
	defaultWriteTimeout      = 10 * time.Second
	defaultIdleTimeout       = 120 * time.Second
	defaultShutdownTimeout   = 10 * time.Second
	defaultMaxConcurrent     = 64

	// maxRequestBodySize bounds the JSON request body, by default. An
	// authorization entry carries a small invocation tree; the library refuses
	// decoded entries past soroauth.MaxDecodeInputBytes, and the base64 form of
	// such an entry plus its JSON framing fits comfortably under this cap. It
	// is a named constant because the integration tests build an oversize body
	// from it.
	maxRequestBodySize = 1 << 20 // 1 MiB
)

// config is the service's resolved configuration. It is built by loadConfig
// from the environment and is the single place every bound is decided, so the
// tests exercise the same defaults main does.
type config struct {
	// Addr is the API listen address, host:port. A non-loopback host requires
	// AuthToken (see loadConfig).
	Addr string
	// MetricsAddr is the Prometheus listen address. "off", "none" or "-"
	// disables the metrics server.
	MetricsAddr string
	// AuthToken is the bearer token /verify requires. Empty means no
	// authentication, which is only allowed on a loopback bind.
	AuthToken string

	ReadTimeout       time.Duration
	ReadHeaderTimeout time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	ShutdownTimeout   time.Duration

	// MaxBodyBytes is the request body cap.
	MaxBodyBytes int64
	// MaxConcurrentRequests bounds the number of /verify handlers running at
	// once. A request over the bound is refused with 503 rather than queued.
	MaxConcurrentRequests int

	// Logger receives the structured request log. main sets a JSON handler on
	// stderr; tests capture it.
	Logger *slog.Logger
}

// defaultConfig is the configuration the integration tests serve, and the base
// loadConfig applies the environment to. It carries no auth token and binds
// loopback, so it is safe by construction.
func defaultConfig() config {
	return config{
		Addr:                  defaultAddr,
		MetricsAddr:           defaultMetricsAddr,
		ReadTimeout:           defaultReadTimeout,
		ReadHeaderTimeout:     defaultReadHeaderTimeout,
		WriteTimeout:          defaultWriteTimeout,
		IdleTimeout:           defaultIdleTimeout,
		ShutdownTimeout:       defaultShutdownTimeout,
		MaxBodyBytes:          maxRequestBodySize,
		MaxConcurrentRequests: defaultMaxConcurrent,
	}
}

// loadConfig resolves the environment into a config, failing closed on a
// malformed bound and on a non-loopback bind with no authentication. getenv is
// os.Getenv in main and a fixture in the tests, so the parsing is exercised
// without mutating the process environment.
func loadConfig(getenv func(string) string) (config, error) {
	cfg := defaultConfig()
	cfg.Addr = valueOr(getenv("ADDR"), cfg.Addr)
	cfg.MetricsAddr = valueOr(getenv("METRICS_ADDR"), cfg.MetricsAddr)
	cfg.AuthToken = getenv("AUTH_TOKEN")

	var err error
	if cfg.ReadTimeout, err = durationEnv(getenv, "READ_TIMEOUT", cfg.ReadTimeout); err != nil {
		return config{}, err
	}
	if cfg.ReadHeaderTimeout, err = durationEnv(getenv, "READ_HEADER_TIMEOUT", cfg.ReadHeaderTimeout); err != nil {
		return config{}, err
	}
	if cfg.WriteTimeout, err = durationEnv(getenv, "WRITE_TIMEOUT", cfg.WriteTimeout); err != nil {
		return config{}, err
	}
	if cfg.IdleTimeout, err = durationEnv(getenv, "IDLE_TIMEOUT", cfg.IdleTimeout); err != nil {
		return config{}, err
	}
	if cfg.MaxBodyBytes, err = int64Env(getenv, "MAX_BODY_BYTES", cfg.MaxBodyBytes); err != nil {
		return config{}, err
	}
	if cfg.MaxConcurrentRequests, err = intEnv(getenv, "MAX_CONCURRENT_REQUESTS", cfg.MaxConcurrentRequests); err != nil {
		return config{}, err
	}

	if cfg.MaxBodyBytes <= 0 {
		return config{}, fmt.Errorf("MAX_BODY_BYTES must be positive, got %d", cfg.MaxBodyBytes)
	}
	if cfg.MaxConcurrentRequests <= 0 {
		return config{}, fmt.Errorf("MAX_CONCURRENT_REQUESTS must be positive, got %d", cfg.MaxConcurrentRequests)
	}
	// Fail closed rather than warn: a warning nobody reads is how a service
	// ends up on a public interface with no authentication.
	if !isLoopbackAddr(cfg.Addr) && cfg.AuthToken == "" {
		return config{}, fmt.Errorf(
			"refusing to bind %q without AUTH_TOKEN: set a bearer token, or bind a loopback address such as 127.0.0.1:8080",
			cfg.Addr)
	}
	return cfg, nil
}

// isLoopbackAddr reports whether a host:port address names a loopback
// interface. An empty host (":8080", every interface) is not loopback.
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// No port: treat the whole string as the host.
		host = addr
	}
	host = strings.Trim(host, "[]")
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// metricsDisabled reports whether the metrics endpoint was turned off by name.
func metricsDisabled(addr string) bool {
	switch strings.ToLower(strings.TrimSpace(addr)) {
	case "", "off", "none", "-":
		return true
	default:
		return false
	}
}

func valueOr(v, fallback string) string {
	if v != "" {
		return v
	}
	return fallback
}

func durationEnv(getenv func(string) string, key string, fallback time.Duration) (time.Duration, error) {
	raw := getenv(key)
	if raw == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return d, nil
}

func int64Env(getenv func(string) string, key string, fallback int64) (int64, error) {
	raw := getenv(key)
	if raw == "" {
		return fallback, nil
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return n, nil
}

func intEnv(getenv func(string) string, key string, fallback int) (int, error) {
	raw := getenv(key)
	if raw == "" {
		return fallback, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return n, nil
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Printf("soroauth-server %s\n", Version)
		return
	}

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfg, err := loadConfig(os.Getenv)
	if err != nil {
		logger.Error("invalid configuration", "error", err)
		os.Exit(1)
	}
	cfg.Logger = logger

	srv := newServer(cfg)

	api := &http.Server{
		Addr:              cfg.Addr,
		Handler:           srv.handler(),
		ReadTimeout:       cfg.ReadTimeout,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
	}

	var metrics *http.Server
	if !metricsDisabled(cfg.MetricsAddr) {
		metrics = &http.Server{
			Addr:              cfg.MetricsAddr,
			Handler:           srv.metricsHandler(),
			ReadTimeout:       cfg.ReadTimeout,
			ReadHeaderTimeout: cfg.ReadHeaderTimeout,
			WriteTimeout:      cfg.WriteTimeout,
			IdleTimeout:       cfg.IdleTimeout,
		}
	}

	errCh := make(chan error, 2)
	go func() {
		logger.Info("starting API server", "addr", cfg.Addr)
		if err := api.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("API server: %w", err)
		}
	}()
	if metrics != nil {
		go func() {
			logger.Info("starting metrics server", "addr", cfg.MetricsAddr)
			if err := metrics.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("metrics server: %w", err)
			}
		}()
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-errCh:
		logger.Error("server failed", "error", err)
		os.Exit(1)
	case <-stop:
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	// API first, then metrics: a scrape during shutdown should still find a
	// live process until the API it describes has drained.
	if err := api.Shutdown(ctx); err != nil {
		logger.Error("API server shutdown failed", "error", err)
		os.Exit(1)
	}
	if metrics != nil {
		if err := metrics.Shutdown(ctx); err != nil {
			logger.Error("metrics server shutdown failed", "error", err)
			os.Exit(1)
		}
	}
	logger.Info("server stopped")
}
