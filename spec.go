package portscan

import (
	"fmt"
	"math"
	"slices"
)

func isValidPort(p int) bool {
	return p > 0 && p <= math.MaxUint16
}

type PortSpec interface {
	expand() ([]uint16, error)
}

func Range(from, to int) PortSpec { return rangeSpec{from: from, to: to} }

type rangeSpec struct{ from, to int }

func (r rangeSpec) expand() ([]uint16, error) {
	if !isValidPort(r.from) || !isValidPort(r.to) {
		return nil, fmt.Errorf("portscan: port range %d-%d is outside [1, %d]", r.from, r.to, math.MaxUint16)
	}
	if r.from > r.to {
		return nil, fmt.Errorf("portscan: reversed port range %d-%d", r.from, r.to)
	}
	ports := make([]uint16, 0, r.to-r.from+1)
	for p := r.from; p <= r.to; p++ {
		ports = append(ports, uint16(p))
	}
	return ports, nil
}

func List(ports ...int) PortSpec { return listSpec(ports) }

type listSpec []int

func (l listSpec) expand() ([]uint16, error) {
	if len(l) == 0 {
		return nil, fmt.Errorf("portscan: empty port list")
	}
	ports := make([]uint16, len(l))
	for i, p := range l {
		if !isValidPort(p) {
			return nil, fmt.Errorf("portscan: port %d is outside [1, %d]", p, math.MaxUint16)
		}
		ports[i] = uint16(p)
	}
	return ports, nil
}

func expandSpecs(specs ...PortSpec) ([]uint16, error) {
	if len(specs) == 0 {
		return nil, fmt.Errorf("portscan: no ports specified")
	}
	var ports []uint16
	for i, spec := range specs {
		if spec == nil {
			return nil, fmt.Errorf("portscan: spec %d is nil", i)
		}
		expanded, err := spec.expand()
		if err != nil {
			return nil, err
		}
		ports = append(ports, expanded...)
	}
	slices.Sort(ports)
	return slices.Compact(ports), nil
}
