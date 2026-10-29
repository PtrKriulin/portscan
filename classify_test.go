package portscan

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
	"time"
)

// TestClassify проверяет классификацию на синтетических ошибках:
// детерминированное покрытие closed/unreachable/timeout/canceled без реальной сети
func TestClassify(t *testing.T) {
	parent, cancel := context.WithTimeout(context.Background(), time.Hour)
	defer cancel()
	deadlineErr := func() error {
		ctx, c := context.WithTimeout(context.Background(), time.Millisecond)
		defer c()
		<-ctx.Done()
		return ctx.Err()
	}()

	tests := []struct {
		name string
		err  error
		want State
	}{
		{"refused", syscall.ECONNREFUSED, StateClosed},
		{"reset", syscall.ECONNRESET, StateClosed},
		{"host-unreachable", syscall.EHOSTUNREACH, StateUnreachable},
		{"net-unreachable", syscall.ENETUNREACH, StateUnreachable},
		{"deadline", deadlineErr, StateTimeout},
		{"canceled", context.Canceled, StateCanceled},
		{"op-err-timeout", &net.OpError{Err: os.NewSyscallError("connect", syscall.ETIMEDOUT)}, StateTimeout},
		{"other", io.EOF, StateError},
	}
	for _, tt := range tests {
		dialCtx, c := context.WithTimeout(context.Background(), time.Hour)
		if got := classify(parent, dialCtx, fmt.Errorf("dial: %w", tt.err)); got != tt.want {
			t.Errorf("%s: classify = %v, want %v", tt.name, got, tt.want)
		}
		c()
	}

	if got := classify(context.Background(), context.Background(), errors.New("x")); got != StateError {
		t.Errorf("no deadline + other = %v, want error", got)
	}
}
