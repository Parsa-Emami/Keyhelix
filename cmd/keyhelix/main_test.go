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
		done <- serve(ctx, "127.0.0.1:0", writer)
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
	for _, path := range []string{"/api/v1/secrets", "/healthz/extra"} {
		response, err := client.Get("http://" + ready.Address + path)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != 404 {
			t.Fatalf("unexpected route admitted: %s", path)
		}
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
		if err := serve(context.Background(), address, io.Discard); err == nil {
			t.Fatalf("accepted %s", address)
		}
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := serve(context.Background(), listener.Addr().String(), io.Discard); err == nil {
		t.Fatal("occupied port accepted")
	}
}
