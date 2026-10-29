package portscan

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
)

type target struct {
	host string
	ip   net.IP
	err  error
}

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
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			out = append(out, target{host: h, err: err})
			continue
		}
		for _, addr := range addrs {
			out = appendTarget(out, seen, h, addr.IP)
		}
	}
	return out, nil
}

func appendTarget(out []target, seen map[string]struct{}, host string, ip net.IP) []target {
	key := host + "\x00" + ip.String()
	if _, dup := seen[key]; dup {
		return out
	}
	seen[key] = struct{}{}
	return append(out, target{host: host, ip: ip})
}

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
