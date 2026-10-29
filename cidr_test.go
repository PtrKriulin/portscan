package portscan_test

import (
	"context"
	"net"
	"testing"

	"portscan"
)

func cidrResults(t *testing.T, hosts []string) []portscan.Result {
	t.Helper()
	s := mustScanner(t)
	results, err := s.Scan(context.Background(), hosts, portscan.List(1))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	var rows []portscan.Result
	for r := range results {
		rows = append(rows, r)
	}
	return rows
}

func TestScanCIDR(t *testing.T) {
	// 127.0.0.0/29 — восемь loopback адресов; listener слушает на 127.0.0.1,
	// остальные семь адресов диапазона дают closed
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	s := mustScanner(t)
	results, err := s.Scan(context.Background(), []string{"127.0.0.0/29"}, portscan.List(int(port)))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	opens := 0
	for r := range results {
		if r.IP == nil {
			t.Fatalf("CIDR result has no IP: %+v", r)
		}
		if r.State == portscan.StateOpen {
			opens++
			if r.IP.String() != "127.0.0.1" {
				t.Errorf("open at %v, want 127.0.0.1", r.IP)
			}
		}
	}
	if opens != 1 {
		t.Errorf("got %d open results, want 1", opens)
	}
}

func TestCIDRDedupAndMix(t *testing.T) {
	// Литерал и /32 одного адреса дают один результат.
	rows := cidrResults(t, []string{"127.0.0.1", "127.0.0.1/32"})
	if len(rows) != 1 {
		t.Fatalf("got %d results, want 1 after dedup", len(rows))
	}
}

func TestCIDRValidation(t *testing.T) {
	cases := map[string]string{
		"127.0.0.1/24":    "host bits",
		"0.0.0.0/0":       "too many addresses",
		"10.0.0.0/200":    "invalid",
		"not-a-cidr/8":    "invalid",
		"::ffff:0.0.0.0/": "invalid",
	}
	s := mustScanner(t)
	for h, want := range cases {
		_, err := s.Scan(context.Background(), []string{h}, portscan.List(80))
		if err == nil {
			t.Errorf("CIDR %q accepted, want error (%s)", h, want)
		}
	}
}
