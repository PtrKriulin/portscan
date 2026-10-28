package portscan_test

import (
	"context"
	"net"
	"testing"
	"time"

	"portscan"
)

/*
Меряет общий путь сканера на быстрой цели:
открытый listener на loopback плюс 255 закрытых портов, каждый из
которых отвечает econnrefused мгновенно
*/
func BenchmarkScanLoopback(b *testing.B) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	s, err := portscan.New(
		portscan.WithConcurrency(64),
		portscan.WithConnectTimeout(500*time.Millisecond),
	)
	if err != nil {
		b.Fatal(err)
	}
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		results, err := s.Scan(ctx, []string{"127.0.0.1"}, portscan.Range(1, 256))
		if err != nil {
			b.Fatal(err)
		}
		for r := range results {
			if r.Port == uint16(port) && r.State != portscan.StateOpen {
				b.Fatalf("open listener reported as %v", r.State)
			}
		}
	}
}

/*
Худший случай для планировщика воркеров:
TEST-NET-1 (192.0.2.1) молча теряет пакеты, каждая попытка
упирается в таймаут и держит слот воркера до его истечения
*/
func BenchmarkScanTimedOut(b *testing.B) {
	s, err := portscan.New(
		portscan.WithConcurrency(64),
		portscan.WithConnectTimeout(100*time.Millisecond),
	)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		results, err := s.Scan(context.Background(), []string{"192.0.2.1"}, portscan.Range(1, 64))
		if err != nil {
			b.Fatal(err)
		}
		for range results {
		}
	}
}
