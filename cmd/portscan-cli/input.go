package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"portscan"
)

func askTargets(mode string, in *bufio.Scanner) ([]string, []portscan.PortSpec, error) {
	switch strings.TrimSpace(mode) {
	case "1":
		hostsLine, err := askLine(in, "Хосты через запятую (например example.com,10.0.0.1)", "выход")
		if err != nil {
			return nil, nil, io.EOF
		}
		portsLine, err := askLine(in, "Порты через запятую (например 22,80,8000-9000)", "выход")
		if err != nil {
			return nil, nil, io.EOF
		}
		specs, err := parsePortSpecs(portsLine)
		return splitValues(hostsLine), specs, err
	case "2":
		jobs := showJobs()
		if len(jobs) == 0 {
			return nil, nil, errors.New("portscan-cli: файлы целей в /data/input не найдены")
		}
		line, err := askLine(in, "Номер файла или имя (например job.json)", "выход")
		if err != nil {
			return nil, nil, io.EOF
		}
		path := jobPath(line, jobs)
		if path == "" {
			return nil, nil, fmt.Errorf("portscan-cli: файл %q не найден в /data/input", line)
		}
		j, err := readJob(path)
		if err != nil {
			return nil, nil, fmt.Errorf("portscan-cli: %w", err)
		}
		specs, err := parsePortSpecs(strings.Join(j.Ports, ","))
		return j.Hosts, specs, err
	}
	return nil, nil, fmt.Errorf("portscan-cli: неизвестный режим %q — введите 1 или 2", strings.TrimSpace(mode))
}

func askLine(in *bufio.Scanner, prompt, emptyHint string) (string, error) {
	fmt.Printf("%s [пусто — %s]: ", prompt, emptyHint)
	if !in.Scan() {
		fmt.Println()
		return "", io.EOF
	}
	line := strings.TrimSpace(in.Text())
	if line == "" {
		return "", io.EOF
	}
	return line, nil
}

func splitValues(s string) []string {
	var values []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			values = append(values, part)
		}
	}
	return values
}

func parsePortSpecs(specs string) ([]portscan.PortSpec, error) {
	var out []portscan.PortSpec
	for _, part := range splitValues(specs) {
		if from, to, err := parseRange(part); err == nil {
			out = append(out, portscan.Range(from, to))
		} else if !errors.Is(err, errNotRange) {
			return nil, err
		} else if port, perr := strconv.Atoi(part); perr == nil {
			out = append(out, portscan.List(port))
		} else {
			return nil, fmt.Errorf("portscan-cli: некорректный порт %q", part)
		}
	}
	return out, nil
}

var errNotRange = errors.New("not a range")

func parseRange(s string) (from, to int, err error) {
	left, right, found := strings.Cut(s, "-")
	if !found {
		return 0, 0, errNotRange
	}
	from, err = strconv.Atoi(strings.TrimSpace(left))
	if err != nil {
		return 0, 0, errNotRange
	}
	to, err = strconv.Atoi(strings.TrimSpace(right))
	if err != nil {
		return 0, 0, errNotRange
	}
	return from, to, nil
}
