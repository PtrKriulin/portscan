package portscan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// ip == nil значит хост не разрешился
type target struct {
	host string
	ip   net.IP
	err  error
}

// IP-литералы как есть, DNS-имена дают цель на каждый адрес, дубли убираем
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
		if strings.Contains(h, "/") {
			addrs, err := cidrAddrs(h)
			if err != nil {
				return nil, err
			}
			for _, ip := range addrs {
				out = appendTarget(out, seen, h, ip)
			}
			continue
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
				// не найден - исход отдельного хоста а не всего скана
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

// хостовые биты и гигантские префиксы (> /16) - ошибка а не молчивый resize,
// иначе 0.0.0.0/0 развернется в 4 млрд адресов; network и broadcast включаем
func cidrAddrs(host string) ([]net.IP, error) {
	p, err := netip.ParsePrefix(host)
	if err != nil {
		return nil, fmt.Errorf("portscan: invalid cidr %q: %w", host, err)
	}
	if p.Masked() != p {
		return nil, fmt.Errorf("portscan: invalid cidr %q: contains host bits", host)
	}
	const maxHostBits = 16
	if p.Bits() < p.Addr().BitLen()-maxHostBits {
		return nil, fmt.Errorf("portscan: cidr %q: too many addresses, use /%d or smaller", host, p.Addr().BitLen()-maxHostBits)
	}
	var out []net.IP
	for addr := p.Addr(); p.Contains(addr); addr = addr.Next() {
		out = append(out, net.IP(addr.AsSlice()))
	}
	return out, nil
}
