package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"time"

	"portscan"
)

func main() {
	scanner, err := portscan.New()
	if err != nil {
		fatal(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	in := bufio.NewScanner(os.Stdin)
	for {
		mode, err := askLine(in, "Режим: 1 — ручной ввод, 2 — файл целей из /data/input", "выход")
		if err != nil {
			return
		}
		hosts, specs, err := askTargets(mode, in)
		if err != nil {
			fmt.Println("ошибка:", err)
			continue
		}
		if rows, ok := printScan(ctx, scanner, hosts, specs); ok {
			if answer, err := askLine(in, "Сохранить результаты в /data/output? [y/N]", "нет"); err != nil {
				return
			} else if isYes(answer) {
				path, err := resultPath()
				if err != nil {
					fmt.Println("ошибка сохранения:", err)
				} else if err := saveResults(path, rows); err != nil {
					fmt.Println("ошибка сохранения:", err)
				} else {
					fmt.Println("сохранено:", path)
				}
			}
		} else {
			return
		}
	}
}

func printScan(ctx context.Context, scanner *portscan.Scanner, hosts []string, specs []portscan.PortSpec) ([]portscan.Result, bool) {
	results, err := scanner.Scan(ctx, hosts, specs...)
	if err != nil {
		fmt.Println("ошибка:", err)
		return nil, ctx.Err() == nil
	}
	var rows []portscan.Result
	for r := range results {
		rows = append(rows, r)
	}
	printResults(os.Stdout, rows)
	if ctx.Err() != nil {
		fmt.Println("сканирование прервано")
		return nil, false
	}
	return rows, true
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "portscan-cli:", err)
	os.Exit(1)
}

func ms(d time.Duration) float64 { return d.Seconds() * 1000 }
