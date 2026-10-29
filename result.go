package portscan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"
)

type State int

const (
	StateOpen State = iota
	StateClosed
	StateTimeout
	StateUnreachable
	StateCanceled
	StateError
)

func (s State) String() string {
	switch s {
	case StateOpen:
		return "open"
	case StateClosed:
		return "closed"
	case StateTimeout:
		return "timeout"
	case StateUnreachable:
		return "unreachable"
	case StateCanceled:
		return "canceled"
	case StateError:
		return "error"
	default:
		return fmt.Sprintf("state(%d)", int(s))
	}
}

func classify(ctx, dialCtx context.Context, err error) State {
	if errors.Is(err, context.Canceled) {
		return StateCanceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		dialDeadline, _ := dialCtx.Deadline()
		parentDeadline, hasParent := ctx.Deadline()
		if ctx.Err() != nil && hasParent && !dialDeadline.Before(parentDeadline) {
			return StateCanceled
		}
		return StateTimeout
	}

	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Timeout() {
		return StateTimeout
	}

	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case syscall.ECONNREFUSED:
			fallthrough
		case syscall.ECONNRESET:
			return StateClosed
		case syscall.ETIMEDOUT:
			return StateTimeout
		case syscall.EHOSTUNREACH, syscall.ENETUNREACH,
			syscall.EHOSTDOWN, syscall.ENETDOWN,
			syscall.ECONNABORTED, syscall.ENETRESET:
			return StateUnreachable
		case syscall.EACCES, syscall.EPERM:
			return StateError
		}
	}
	return StateError
}

type Result struct {
	Host     string
	IP       net.IP
	Port     uint16
	State    State
	Duration time.Duration
	Err      error
}
