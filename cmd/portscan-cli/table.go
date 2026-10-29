package main

import (
	"fmt"
	"io"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"

	"portscan"
)

func printResults(w io.Writer, results []portscan.Result) {
	const (
		colHost = iota
		colIP
		colVersion
		colPort
		colState
		colErr
		colTime
		colCount
	)
	headers := []string{"HOST", "IP", "Ver", "PORT", "STATUS", "ERR", "TIME"}

	rows := append([]portscan.Result(nil), results...)
	slices.SortFunc(rows, func(a, b portscan.Result) int {
		if a.Port != b.Port {
			return int(a.Port) - int(b.Port)
		}
		return ipCompare(a.IP, b.IP)
	})

	cells := make([][]string, len(rows))
	for i, r := range rows {
		version := "IPv4"
		if r.IP.To4() == nil {
			version = "IPv6"
		}
		errText := "—"
		if r.Err != nil {
			errText = r.Err.Error()
		}
		cells[i] = []string{r.Host, r.IP.String(), version, fmt.Sprint(r.Port), r.State.String(), errText, fmtDuration(r.Duration)}
	}

	widths := make([]int, colCount)
	for c, h := range headers {
		widths[c] = runeLen(h)
	}
	for _, row := range cells {
		for c, text := range row {
			widths[c] = max(widths[c], runeLen(text))
		}
	}

	head := make([]string, colCount)
	for c, h := range headers {
		if c == colPort || c == colTime {
			head[c] = lpad(h, widths[c])
		} else {
			head[c] = rpad(h, widths[c])
		}
	}
	title := strings.Join(head, "  ")
	fmt.Fprintln(w, title)
	fmt.Fprintln(w, strings.Repeat("-", runeLen(title)))
	for _, row := range cells {
		parts := make([]string, colCount)
		for c, text := range row {
			if c == colPort || c == colTime {
				parts[c] = lpad(text, widths[c])
			} else {
				parts[c] = rpad(text, widths[c])
			}
		}
		fmt.Fprintln(w, strings.Join(parts, "  "))
	}
}

func fmtDuration(d time.Duration) string {
	return strconv.FormatFloat(ms(d), 'f', 3, 64) + "ms"
}

func runeLen(s string) int { return len([]rune(s)) }

func rpad(s string, w int) string {
	if pad := w - runeLen(s); pad > 0 {
		return s + strings.Repeat(" ", pad)
	}
	return s
}

func lpad(s string, w int) string {
	if pad := w - runeLen(s); pad > 0 {
		return strings.Repeat(" ", pad) + s
	}
	return s
}

func ipCompare(a, b net.IP) int {
	ab, bb := a.To16(), b.To16()
	switch {
	case ab == nil && bb == nil:
		return 0
	case ab == nil:
		return -1
	case bb == nil:
		return 1
	}
	return slices.Compare(ab, bb)
}
