package portscan

import (
	"fmt"
	"runtime"
	"time"
)

// дефолт условный: задача сетевая а не процессорная,
// для больших объемов задавайте WithConcurrency явно
func defaultConcurrency() int {
	return runtime.NumCPU()
}

type Scanner struct {
	concurrency int
	timeout     time.Duration
}

type Option func(*Scanner)

func WithConcurrency(n int) Option {
	return func(s *Scanner) { s.concurrency = n }
}

func WithConnectTimeout(d time.Duration) Option {
	return func(s *Scanner) { s.timeout = d }
}

func New(opts ...Option) (*Scanner, error) {
	s := &Scanner{concurrency: defaultConcurrency(), timeout: time.Second}
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}
	if s.concurrency < 1 {
		return nil, fmt.Errorf("portscan: concurrency must be > 0, got %d", s.concurrency)
	}
	if s.timeout <= 0 {
		return nil, fmt.Errorf("portscan: connect timeout must be > 0, got %s", s.timeout)
	}
	return s, nil
}
