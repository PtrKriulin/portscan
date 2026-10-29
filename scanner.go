package portscan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strconv"
	"sync"
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

// Scan валидирует ввод и резолвит хостов синхронно - ошибку ввода отдаем до
// старта горутин. Ошибка резолвинга одного имени не прерывает скан, придет
// отдельным Result с ip == nil. Канал закрывается после всех результатов
func (s *Scanner) Scan(ctx context.Context, hosts []string, specs ...PortSpec) (<-chan Result, error) {
	if ctx == nil {
		return nil, errors.New("portscan: nil context")
	}
	ports, err := expandSpecs(specs...)
	if err != nil {
		return nil, err
	}
	targets, err := resolveTargets(ctx, hosts)
	if err != nil {
		return nil, err
	}
	return s.run(ctx, targets, ports), nil
}

// select на каждой отправке - медленный читатель не должен блокировать отмену
func (s *Scanner) run(ctx context.Context, targets []target, ports []uint16) <-chan Result {
	tasks := make(chan task, s.concurrency)
	results := make(chan Result, s.concurrency)

	go func() {
		defer close(tasks)
		for _, t := range targets {
			if t.ip == nil {
				if !send(ctx, results, Result{Host: t.host, State: StateError, Err: t.err}) {
					return
				}
				continue
			}
			for _, port := range ports {
				select {
				case tasks <- task{target: t, port: port}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	var wg sync.WaitGroup
	wg.Add(s.concurrency)
	for range s.concurrency {
		go func() {
			defer wg.Done()
			for t := range tasks {
				if !send(ctx, results, s.check(ctx, t)) {
					return
				}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	return results
}

type task struct {
	target target
	port   uint16
}

func (s *Scanner) check(ctx context.Context, t task) Result {
	start := time.Now()
	dialCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	addr := net.JoinHostPort(t.target.ip.String(), strconv.Itoa(int(t.port)))
	var dialer net.Dialer
	conn, err := dialer.DialContext(dialCtx, "tcp", addr)
	res := Result{
		Host:     t.target.host,
		IP:       t.target.ip,
		Port:     t.port,
		Duration: time.Since(start),
	}
	if err != nil {
		res.State = classify(ctx, dialCtx, err)
		res.Err = err
		return res
	}
	_ = conn.Close()
	res.State = StateOpen
	return res
}

func send(ctx context.Context, results chan<- Result, res Result) bool {
	select {
	case results <- res:
		return true
	case <-ctx.Done():
		return false
	}
}
