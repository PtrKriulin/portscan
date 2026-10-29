package main

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"portscan"
)

func FuzzParseRange(f *testing.F) {
	f.Add("8000-9000")
	f.Add("1-2")
	f.Add("80")
	f.Add("1000-1")
	f.Add("-5-10")
	f.Add("abc-def")
	f.Add("1-")
	f.Fuzz(func(t *testing.T, s string) {
		from, to, err := parseRange(s)
		if err != nil {
			if err != errNotRange {
				t.Fatalf("unexpected error: %v", err)
			}
			return
		}
		left, right, _ := strings.Cut(s, "-")
		if _, e1 := strconv.Atoi(strings.TrimSpace(left)); e1 != nil {
			t.Fatalf("parseRange(%q) succeeded, but left part %q is not a number", s, left)
		}
		if _, e2 := strconv.Atoi(strings.TrimSpace(right)); e2 != nil {
			t.Fatalf("parseRange(%q) succeeded, but right part %q is not a number", s, right)
		}
		if got, want := from, atoi(t, left); got != want {
			t.Fatalf("parseRange(%q) left bound = %d, want %d", s, got, want)
		}
		if got, want := to, atoi(t, right); got != want {
			t.Fatalf("parseRange(%q) right bound = %d, want %d", s, got, want)
		}
	})
}

func atoi(t *testing.T, s string) int {
	t.Helper()
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		t.Fatalf("internal: %v", err)
	}
	return n
}

func FuzzParsePortSpecs(f *testing.F) {
	f.Add("22, 80, 8000-9000")
	f.Add("")
	f.Add("0")
	f.Add("65536-65537")
	f.Add(",,")
	f.Add("80-,90")
	f.Fuzz(func(t *testing.T, s string) {
		specs, err := parsePortSpecs(s)
		if err != nil || len(specs) == 0 {
			return
		}
		scanner, err := portscan.New(portscan.WithConcurrency(1), portscan.WithConnectTimeout(time.Millisecond))
		if err != nil {
			t.Fatal(err)
		}
		results, err := scanner.Scan(context.Background(), []string{"127.0.0.1"}, specs...)
		if err != nil {
			if !strings.HasPrefix(err.Error(), "portscan:") {
				t.Fatalf("specs parsed from %q rejected with non-package error: %v", s, err)
			}
			return
		}
		for range results {
		}
	})
}
