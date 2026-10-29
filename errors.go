package portscan

import "errors"

// Ошибки валидации входных данных. Возвращаются из Scan до любой
// сетевой активности. Вызывающий код может проверять через errors.Is
var (
	ErrNoHosts            = errors.New("portscan: no hosts specified")
	ErrEmptyHost          = errors.New("portscan: empty host")
	ErrNoPorts            = errors.New("portscan: no ports specified")
	ErrPortOutOfRange     = errors.New("portscan: port outside [1, 65535]")
	ErrReversedRange      = errors.New("portscan: reversed port range")
	ErrNilContext         = errors.New("portscan: nil context")
	ErrInvalidCIDR        = errors.New("portscan: invalid cidr")
	ErrNilSpec            = errors.New("portscan: nil port spec")
	ErrInvalidConcurrency = errors.New("portscan: concurrency must be > 0")
	ErrInvalidTimeout     = errors.New("portscan: connect timeout must be > 0")
)
