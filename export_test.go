package portscan

import (
	"context"
	"net"
)

// SetTestDial подменяет функцию подключения у сканера
// только для тестов, в обычном коде не используется
func SetTestDial(s *Scanner, f func(context.Context, string, string) (net.Conn, error)) {
	s.dial = f
}
