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

/*
классификация ошибки в State - только по типам (errors.Is/As), по тексту нельзя,
текст зависит от ОС и локали

тонкий момент: DeadlineExceeded приходит и при отмене родительского контекста
и при истечении нашего таймаута попытки, сравниваем дедлайны между собой -
родительский истек не позже дедлайна попытки значит отмену инициировал
вызывающий (canceled), иначе попытка не уложилась в свой таймаут (timeout)
без этого различия при отмене все незавершенные попытки ушли бы как timeout
*/
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
	// часть таймаутов не заворачивается в DeadlineExceeded
	if errors.As(err, &opErr) && opErr.Timeout() {
		return StateTimeout
	}

	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case syscall.ECONNREFUSED:
			// RST на хендшейке, часть стеков отдает ECONNRESET
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
			// локальный запрет, до хоста не дошли - error а не unreachable
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
