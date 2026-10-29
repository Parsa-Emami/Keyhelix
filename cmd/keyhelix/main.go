package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/parsa-emami/keyhelix/internal/contracts"
)

const version = "0.0.1"

func health() map[string]any {
	return map[string]any{
		"status":    "ok",
		"scope":     "engine-runtime",
		"version":   version,
		"toolchain": runtime.Version(),
		"coreReady": false,
	}
}

func readiness() map[string]any {
	return map[string]any{
		"status":    "ready",
		"scope":     "engine-runtime",
		"version":   version,
		"toolchain": runtime.Version(),
		"storage":   "ready",
		"coreReady": false,
	}
}

func serve(ctx context.Context, address string, ready io.Writer) error {
	host, port, err := net.SplitHostPort(address)
	number, portErr := strconv.Atoi(port)
	if err != nil || portErr != nil || number < 0 || number > 65535 || (host != "127.0.0.1" && host != "::1") {
		return errors.New("engine listen address must be loopback with a valid port")
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	defer listener.Close()
	server := &http.Server{
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       2 * time.Second,
		WriteTimeout:      2 * time.Second,
		IdleTimeout:       5 * time.Second,
		MaxHeaderBytes:    16384,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Path != "/healthz" && r.URL.Path != "/readyz" {
				w.WriteHeader(http.StatusNotFound)
				io.WriteString(w, `{"error":"not_found"}`)
				return
			}
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				w.Header().Set("Allow", "GET, HEAD")
				w.WriteHeader(http.StatusMethodNotAllowed)
				io.WriteString(w, `{"error":"method_not_allowed"}`)
				return
			}
			if r.Method == http.MethodGet {
				if r.URL.Path == "/readyz" {
					json.NewEncoder(w).Encode(readiness())
				} else {
					json.NewEncoder(w).Encode(health())
				}
			}
		}),
	}
	if err := json.NewEncoder(ready).Encode(map[string]any{
		"service": "keyhelix-engine",
		"address": listener.Addr().String(),
		"pid":     os.Getpid(),
	}); err != nil {
		return err
	}
	stopped := make(chan error, 1)
	served := make(chan struct{})
	defer close(served)
	go func() {
		select {
		case <-ctx.Done():
			shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err := server.Shutdown(shutdown)
			if err != nil {
				server.Close()
			}
			stopped <- err
		case <-served:
		}
	}()
	err = server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return <-stopped
	}
	return err
}

func main() {
	address := flag.String("listen", "127.0.0.1:0", "loopback listen address")
	showVersion := flag.Bool("version", false, "print runtime version and exit")
	validateSecret := flag.Bool("validate-secret", false, "validate secret metadata from stdin")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "unexpected engine arguments")
		os.Exit(1)
	}
	if *showVersion {
		json.NewEncoder(os.Stdout).Encode(health())
		return
	}
	if *validateSecret {
		ctx, cancel := context.WithTimeout(context.Background(), contracts.ValidationTimeout)
		defer cancel()
		result := contracts.Validate(ctx, os.Stdin, version)
		json.NewEncoder(os.Stdout).Encode(result)
		if result.Status != "unverified" || !result.Result.Valid {
			os.Exit(1)
		}
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		io.Copy(io.Discard, os.Stdin)
		stop()
	}()
	if err := serve(ctx, *address, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
