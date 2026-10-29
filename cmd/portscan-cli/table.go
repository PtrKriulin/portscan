package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"portscan"
)

/*
печатает результаты выровненной таблицей: шапка, ширины
колонок по фактическому содержимому, сортировка по порту и адресу
*/
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
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Port != rows[j].Port {
			return rows[i].Port < rows[j].Port
		}
		return ipLess(rows[i].IP, rows[j].IP)
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

func ipLess(a, b net.IP) bool {
	ab, bb := a.To16(), b.To16()
	if ab == nil || bb == nil {
		return ab == nil && bb != nil
	}
	return bytes.Compare(ab, bb) < 0
}
