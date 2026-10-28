package portscan

import (
	"math"
	"slices"
	"testing"
)

func FuzzExpandSpecs(f *testing.F) {
	f.Add(1, 1)
	f.Add(22, 80)
	f.Add(0, 10)
	f.Add(65535, 65536)
	f.Add(1000, 1)
	f.Add(math.MaxInt32, math.MaxInt32)
	f.Fuzz(func(t *testing.T, from, to int) {
		ports, err := Range(from, to).expand()
		if err != nil {
			if isValidPort(from) && isValidPort(to) && from <= to {
				t.Fatalf("valid range %d-%d rejected: %v", from, to, err)
			}
			return
		}
		if !isValidPort(from) || !isValidPort(to) || from > to {
			t.Fatalf("invalid range %d-%d accepted", from, to)
		}
		if len(ports) != to-from+1 {
			t.Fatalf("got %d ports, want %d", len(ports), to-from+1)
		}
		if !slices.IsSorted(ports) {
			t.Fatal("expanded ports are not sorted")
		}
		if slices.Contains(ports, 0) {
			t.Fatal("port 0 in result")
		}
		if uint16(from) != uint16(ports[0]) || uint16(to) != uint16(ports[len(ports)-1]) {
			t.Fatalf("bounds mismatch: got %d-%d, want %d-%d", ports[0], ports[len(ports)-1], from, to)
		}
	})
}
