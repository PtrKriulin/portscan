package portscan

import (
	"context"
	"errors"
	"fmt"
	"net"
)

// цель сканирования; неразрешимый хост дает ip == nil и не-nil err
type target struct {
	host string
	ip   net.IP
	err  error
}

// resolveTargets преобразует строки хостов в цели.
// IP-литералы используются как есть, DNS-имена разрешаются с контекстом
// и дают цель на каждый адрес. Дубликаты адресов убираются.
// Ошибка возвращается для пустого списка или пустой строки,
// неразрешимый хост становится целью с ip == nil, скан не прерывает
func resolveTargets(ctx context.Context, hosts []string) ([]target, error) {
	if len(hosts) == 0 {
		return nil, fmt.Errorf("portscan: no hosts specified")
	}
	out := make([]target, 0, len(hosts))
	seen := make(map[string]struct{})
	for _, h := range hosts {
		if h == "" {
			return nil, fmt.Errorf("portscan: empty host")
		}
		if ip := net.ParseIP(h); ip != nil {
			out = appendTarget(out, seen, h, ip)
			continue
		}
		addrs, err := net.DefaultResolver.LookupIPAddr(ctx, h)
		if err != nil {
			switch {
			case ctx.Err() != nil:
				return nil, ctx.Err()
			case isNotFound(err):
				// хост не найден - исход отдельного хоста, не всего скана
				out = append(out, target{host: h, err: err})
			default:
				return nil, fmt.Errorf("portscan: resolving %q: %w", h, err)
			}
			continue
		}
		for _, addr := range addrs {
			out = appendTarget(out, seen, h, addr.IP)
		}
	}
	return out, nil
}

// дедуп по адресу
func appendTarget(out []target, seen map[string]struct{}, host string, ip net.IP) []target {
	key := ip.String()
	if _, dup := seen[key]; dup {
		return out
	}
	seen[key] = struct{}{}
	return append(out, target{host: host, ip: ip})
}

func isNotFound(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound
}
