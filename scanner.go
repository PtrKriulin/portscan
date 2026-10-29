package portscan

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"
)

// дефолт 100: задача сетевая (I/O-bound), ограничена сокетами и таймаутами,
// а не числом ядер; для больших объемов задаем WithConcurrency явно
func defaultConcurrency() int {
	return 100
}

// Scanner выполняет конкурентные TCP connect проверки портов
// поля приватные, настройка только через опции в New
type Scanner struct {
	concurrency int
	timeout     time.Duration
	sem         chan struct{} // общий лимит на сканер, а не на один вызов Scan
	dial        func(context.Context, string, string) (net.Conn, error)
}

// Option настраивает Scanner
type Option func(*Scanner)

// WithConcurrency задает максимум одновременных подключений
func WithConcurrency(n int) Option {
	return func(s *Scanner) { s.concurrency = n }
}

// WithConnectTimeout задает таймаут одного TCP подключения (не всего скана)
func WithConnectTimeout(d time.Duration) Option {
	return func(s *Scanner) { s.timeout = d }
}

// New создает сканер: дефолты, потом опции, потом валидация
// при некорректных значениях возвращаем ошибку
func New(opts ...Option) (*Scanner, error) {
	s := &Scanner{concurrency: defaultConcurrency(), timeout: time.Second}
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}
	if s.concurrency < 1 {
		return nil, fmt.Errorf("portscan: concurrency must be > 0, got %d: %w", s.concurrency, ErrInvalidConcurrency)
	}
	if s.timeout <= 0 {
		return nil, fmt.Errorf("portscan: connect timeout must be > 0, got %s: %w", s.timeout, ErrInvalidTimeout)
	}
	s.sem = make(chan struct{}, s.concurrency)
	return s, nil
}

// Scan проверяет порты всех хостов и возвращает канал результатов.
// Ошибки валидации и отмены до старта возвращаются как error,
// ошибки отдельных хостов - как Result в канале.
// Канал закрывается один раз после завершения всех проверок или отмены.
func (s *Scanner) Scan(ctx context.Context, hosts []string, specs ...PortSpec) (<-chan Result, error) {
	if ctx == nil {
		return nil, ErrNilContext
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

func (s *Scanner) run(ctx context.Context, targets []target, ports []uint16) <-chan Result {
	tasks := make(chan task, s.concurrency)
	results := make(chan Result, s.concurrency)

	var wg sync.WaitGroup
	wg.Add(s.concurrency + 1) // воркеры + продюсер: close после выхода всех
	go func() {
		defer wg.Done()
		defer close(tasks)
		for _, t := range targets {
			if t.ip == nil {
				if !send(ctx, results, Result{Host: t.host, State: StateError, Err: t.err}) {
					return
				}
				continue
			}
			for _, port := range ports {
				if ctx.Err() != nil {
					return
				}
				select {
				case tasks <- task{target: t, port: port}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	for range s.concurrency {
		go func() {
			defer wg.Done()
			for t := range tasks {
				if ctx.Err() != nil {
					return
				}
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
	s.sem <- struct{}{}
	defer func() { <-s.sem }()
	addr := net.JoinHostPort(t.target.ip.String(), strconv.Itoa(int(t.port)))
	dialCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	dial := s.dial
	if dial == nil {
		var dialer net.Dialer
		dial = dialer.DialContext
	}
	conn, err := dial(dialCtx, "tcp", addr)
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
	// сначала неблокирующая попытка: если контекст уже отменен и буфер
	// пуст, select с двумя готовыми кейсами выбрал бы случайную ветку
	// и результат терялся бы примерно в половине случаев
	select {
	case results <- res:
		return true
	default:
	}
	select {
	case results <- res:
		return true
	case <-ctx.Done():
		return false
	}
}
