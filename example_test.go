package portscan_test

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/PtrKriulin/portscan"
)

func ExampleScanner_Scan() {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	scanner, err := portscan.New(
		portscan.WithConcurrency(100),
		portscan.WithConnectTimeout(500*time.Millisecond),
	)
	if err != nil {
		log.Fatal(err)
	}

	results, err := scanner.Scan(
		context.Background(),
		[]string{"127.0.0.1"},
		portscan.List(port),
	)
	if err != nil {
		log.Fatal(err)
	}

	for result := range results {
		fmt.Println(result.State)
	}

	// Output: open
}
