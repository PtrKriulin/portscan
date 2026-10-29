package portscan_test

import (
	"context"
	"errors"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/PtrKriulin/portscan"
)

func requireNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func mustScanner(t *testing.T) *portscan.Scanner {
	t.Helper()
	s, err := portscan.New(portscan.WithConcurrency(16), portscan.WithConnectTimeout(500*time.Millisecond))
	requireNoError(t, err)
	return s
}

func TestNewValidation(t *testing.T) {
	if _, err := portscan.New(portscan.WithConcurrency(0)); err == nil {
		t.Fatal("expected error for zero concurrency")
	}
	if _, err := portscan.New(portscan.WithConnectTimeout(-time.Second)); err == nil {
		t.Fatal("expected error for negative timeout")
	}
	if _, err := portscan.New(portscan.WithConcurrency(1), portscan.WithConnectTimeout(time.Millisecond)); err != nil {
		t.Fatalf("valid options rejected: %v", err)
	}
}

func TestPortSpecValidation(t *testing.T) {
	cases := []struct {
		name string
		spec portscan.PortSpec
	}{
		{"port zero", portscan.List(0)},
		{"port too big", portscan.List(65536)},
		{"range with zero", portscan.Range(0, 10)},
		{"reversed range", portscan.Range(1000, 1)},
		{"range too big", portscan.Range(65535, 65536)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := mustScanner(t)
			_, err := s.Scan(context.Background(), []string{"127.0.0.1"}, tc.spec)
			if err == nil {
				t.Fatal("expected validation error, got nil")
			}
		})
	}
}

func TestScanEmptyInputs(t *testing.T) {
	s := mustScanner(t)
	ctx := context.Background()
	if _, err := s.Scan(ctx, nil, portscan.List(80)); err == nil {
		t.Error("expected error for empty host list")
	}
	if _, err := s.Scan(ctx, []string{"127.0.0.1"}); err == nil {
		t.Error("expected error for empty port list")
	}
	if _, err := s.Scan(ctx, []string{""}, portscan.List(80)); err == nil {
		t.Error("expected error for empty host string")
	}
}

func TestScanOpenAndClosed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	requireNoError(t, err)
	defer ln.Close()
	openPort := ln.Addr().(*net.TCPAddr).Port
	closedPort := freePort(t, openPort)

	s := mustScanner(t)
	results, err := s.Scan(context.Background(),
		[]string{"127.0.0.1"},
		portscan.List(openPort, closedPort),
	)
	requireNoError(t, err)

	byPort := map[uint16]portscan.State{}
	for r := range results {
		byPort[r.Port] = r.State
	}
	if got := byPort[uint16(openPort)]; got != portscan.StateOpen {
		t.Errorf("open port %d: got state %v, want open", openPort, got)
	}
	if got := byPort[uint16(closedPort)]; got != portscan.StateClosed {
		t.Errorf("closed port %d: got state %v, want closed", closedPort, got)
	}
}

func freePort(t *testing.T, not int) int {
	t.Helper()
	for {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		requireNoError(t, err)
		p := ln.Addr().(*net.TCPAddr).Port
		ln.Close()
		if p != not {
			return p
		}
	}
}

func TestScanIPv6(t *testing.T) {
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	s := mustScanner(t)
	results, err := s.Scan(context.Background(), []string{"::1"}, portscan.List(port))
	requireNoError(t, err)
	var seen bool
	for r := range results {
		seen = true
		if r.State != portscan.StateOpen || r.IP == nil {
			t.Fatalf("unexpected result %+v", r)
		}
	}
	if !seen {
		t.Fatal("no results for IPv6 target")
	}
}

func TestScanDeduplication(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	requireNoError(t, err)
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	s := mustScanner(t)

	results, err := s.Scan(context.Background(),
		[]string{"127.0.0.1", "127.0.0.1", "127.0.0.1"},
		portscan.List(port, port), portscan.List(port),
	)
	requireNoError(t, err)
	count := 0
	for r := range results {
		count++
		if r.Port != uint16(port) {
			t.Fatalf("unexpected result %+v", r)
		}
	}
	if count != 1 {
		t.Errorf("duplicate targets/ports not deduplicated: got %d results, want 1", count)
	}
}

func TestScanUnresolvableHost(t *testing.T) {
	s := mustScanner(t)
	results, err := s.Scan(context.Background(),
		[]string{"portscan-test.invalid.invalid", "127.0.0.1"},
		portscan.List(1),
	)
	requireNoError(t, err)
	n := 0
	for r := range results {
		n++
		if r.State == portscan.StateError && r.Err == nil {
			t.Fatal("error state result must carry Err")
		}
	}
	if n == 0 {
		t.Fatal("no results")
	}
}

func TestScanUnreachableNetwork(t *testing.T) {
	s := mustScanner(t)
	results, err := s.Scan(context.Background(), []string{"192.0.2.1"}, portscan.List(80))
	requireNoError(t, err)
	for r := range results {
		if r.State == portscan.StateOpen {
			t.Skipf("TEST-NET target reported open (transparent network)")
		}
		t.Logf("TEST-NET state in this environment: %v (%.3fs)", r.State, r.Duration.Seconds())
	}
}

func TestScanNoGoroutineLeak(t *testing.T) {
	before := runtime.NumGoroutine()

	// отмененный скан: продюсер, воркеры и closer должны завершиться
	ctx, cancel := context.WithCancel(context.Background())
	s := mustScanner(t)
	results, err := s.Scan(ctx, []string{"127.0.0.1", "192.0.2.1"}, portscan.Range(1, 2000))
	requireNoError(t, err)
	time.Sleep(20 * time.Millisecond)
	cancel()
	for range results {
	}

	// отмененный потребитель: воркеры заблокированы в send, отменяются
	ctx2, cancel2 := context.WithCancel(context.Background())
	results2, err := s.Scan(ctx2, []string{"192.0.2.1"}, portscan.Range(1, 200))
	requireNoError(t, err)
	cancel2()
	<-results2 // канал закрывается и при нечитающем потребителе

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= before+2 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("goroutine leak: before %d, after %d", before, runtime.NumGoroutine())
}

func TestScanCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	s := mustScanner(t)
	results, err := s.Scan(ctx, []string{"192.0.2.1"}, portscan.Range(1, 65535))
	requireNoError(t, err)
	time.Sleep(20 * time.Millisecond)
	cancel()
	canceled, other := 0, 0
	for r := range results {
		if r.State == portscan.StateCanceled {
			canceled++
		} else {
			other++
			if r.State == portscan.StateOpen {
				t.Skipf("TEST-NET target reported open (transparent network)")
			}
		}
	}
	if canceled == 0 {
		t.Fatal("no canceled results reported")
	}
}

func TestScanSlowConsumer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	requireNoError(t, err)
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	s := mustScanner(t)
	results, err := s.Scan(context.Background(), []string{"127.0.0.1"}, portscan.Range(1, 2000))
	requireNoError(t, err)
	count := 0
	for r := range results {
		count++
		if r.Port == uint16(port) && r.State != portscan.StateOpen {
			t.Fatalf("open listener reported as %v", r.State)
		}
	}
	if count != 2000 {
		t.Errorf("got %d results, want 2000", count)
	}
}

func TestScannerReuseAndConcurrentScan(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	requireNoError(t, err)
	defer ln.Close()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	s := mustScanner(t)
	var mu sync.Mutex
	opens := 0
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results, err := s.Scan(context.Background(), []string{"127.0.0.1"}, portscan.List(int(port)))
			if err != nil {
				t.Errorf("scan failed: %v", err)
				return
			}
			for r := range results {
				if r.State == portscan.StateOpen {
					mu.Lock()
					opens++
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	if opens != 8 {
		t.Errorf("got %d open results across 8 concurrent scans, want 8", opens)
	}
}

// валидация возвращает ошибки пригодные для errors.Is
func TestValidationSentinelErrors(t *testing.T) {
	newScanner := func() *portscan.Scanner {
		s, err := portscan.New()
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	cases := []struct {
		name string
		want error
		fn   func() error
	}{
		{"no hosts", portscan.ErrNoHosts, func() error {
			_, err := newScanner().Scan(context.Background(), nil, portscan.List(80))
			return err
		}},
		{"empty host", portscan.ErrEmptyHost, func() error {
			_, err := newScanner().Scan(context.Background(), []string{"  "}, portscan.List(80))
			return err
		}},
		{"no ports", portscan.ErrNoPorts, func() error {
			_, err := newScanner().Scan(context.Background(), []string{"127.0.0.1"})
			return err
		}},
		{"out of range", portscan.ErrPortOutOfRange, func() error {
			_, err := newScanner().Scan(context.Background(), []string{"127.0.0.1"}, portscan.List(0))
			return err
		}},
		{"reversed range", portscan.ErrReversedRange, func() error {
			_, err := newScanner().Scan(context.Background(), []string{"127.0.0.1"}, portscan.Range(100, 1))
			return err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.fn(); !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
		})
	}
}
