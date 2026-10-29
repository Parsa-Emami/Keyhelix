package main

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestLifecycle(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reader, writer := io.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- serve(ctx, "127.0.0.1:0", writer, nil)
		writer.Close()
	}()
	var ready struct{ Address string }
	if err := json.NewDecoder(bufio.NewReader(reader)).Decode(&ready); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 2 * time.Second}
	response, err := client.Get("http://" + ready.Address + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 200 || result["scope"] != "engine-runtime" || result["coreReady"] != false || result["version"] != "0.0.1" || !strings.HasPrefix(result["toolchain"].(string), "go1.") {
		t.Fatalf("invalid health: %v", result)
	}
	response, err = client.Get("http://" + ready.Address + "/api/v1/secrets")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("unconfigured engine API must fail explicitly, got %d", response.StatusCode)
	}
	response, err = client.Get("http://" + ready.Address + "/healthz/extra")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("unexpected route admitted: %d", response.StatusCode)
	}
	response, err = client.Post("http://"+ready.Address+"/healthz", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 405 {
		t.Fatal("mutation admitted")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("shutdown deadline")
	}
	if connection, err := net.DialTimeout("tcp", ready.Address, time.Second); err == nil {
		connection.Close()
		t.Fatal("listener survived shutdown")
	}
}

func TestRejectsUnsafeAndOccupiedAddresses(t *testing.T) {
	for _, address := range []string{"0.0.0.0:0", "example.invalid:80", "[::]:0", "127.0.0.1:bad"} {
		if err := serve(context.Background(), address, io.Discard, nil); err == nil {
			t.Fatalf("accepted %s", address)
		}
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := serve(context.Background(), listener.Addr().String(), io.Discard, nil); err == nil {
		t.Fatal("occupied port accepted")
	}
}
