package portscan

import (
	"net"
	"testing"
)

// FuzzCIDRAddrs проверяет, что cidrAddrs не зацикливается и не паникует
// на произвольных префиксах, а развёрнутые адреса всегда внутри диапазона
func FuzzCIDRAddrs(f *testing.F) {
	f.Add("0.0.0.0/32")
	f.Add("10.0.0.0/29")
	f.Add("255.255.255.255/32")
	f.Add("::1/128")
	f.Add("fd00::/126")
	f.Add("2001:db8::/112")
	f.Fuzz(func(t *testing.T, s string) {
		addrs, err := cidrAddrs(s)
		if err != nil {
			return // невалидные или слишком большие диапазоны отклонены
		}
		if len(addrs) == 0 {
			t.Fatalf("%s: empty expansion", s)
		}
		_, pnet, perr := net.ParseCIDR(s)
		if perr != nil {
			return
		}
		for _, a := range addrs {
			if !pnet.Contains(a) {
				t.Fatalf("%s: address %s outside prefix", s, a)
			}
		}
	})
}
