package main

import (
	"net"
	"strings"
	"testing"

	"portscan"
)

func TestPrintResultsSortingAndLayout(t *testing.T) {
	samePort := uint16(80)
	rows := []portscan.Result{
		{Host: "h1", IP: net.ParseIP("192.168.2.10"), Port: samePort, State: portscan.StateOpen},
		{Host: "h2", IP: net.ParseIP("192.168.2.2"), Port: samePort, State: portscan.StateClosed},
		{Host: "h3", IP: net.ParseIP("10.0.0.1"), Port: 22, State: portscan.StateOpen},
	}

	var sb strings.Builder
	printResults(&sb, rows)
	out := sb.String()
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != len(rows)+2 { // шапка + разделитель
		t.Fatalf("got %d lines, want %d", len(lines), len(rows)+2)
	}

	wantOrder := []string{"10.0.0.1", "192.168.2.2", "192.168.2.10"}
	for i, ip := range wantOrder {
		line := lines[2+i]
		idx := strings.Index(line, ip)
		if idx < 0 {
			t.Fatalf("line %d does not contain %s: %q", i, ip, line)
		}
		if i > 0 && strings.Index(lines[1+i], wantOrder[i-1]) > idx {
			t.Errorf("row %d (%s) sorts after row %d (%s)", i, ip, i-1, wantOrder[i-1])
		}
	}
}

func TestPrintResultsEmpty(t *testing.T) {
	var sb strings.Builder
	printResults(&sb, nil)
	if sb.Len() == 0 {
		t.Fatal("empty results must still print the header")
	}
}
