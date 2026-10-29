package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"portscan"
)

const (
	inputDir  = "/data/input"
	outputDir = "/data/output"
)

type job struct {
	Hosts []string `json:"hosts"`
	Ports []string `json:"ports"`
}

type resultOut struct {
	Host      string  `json:"host"`
	IP        string  `json:"ip"`
	Port      uint16  `json:"port"`
	State     string  `json:"state"`
	Duration  float64 `json:"duration_ms"`
	ErrorText string  `json:"error,omitempty"`
}

func resultPath() (string, error) {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return "", err
	}
	return filepath.Join(outputDir, "results-"+time.Now().Format("20060102150405")+".json"), nil
}

func isYes(answer string) bool {
	switch strings.ToLower(answer) {
	case "y", "yes", "да":
		return true
	}
	return false
}

func showJobs() []string {
	jobs, err := listJobs()
	if err != nil || len(jobs) == 0 {
		return nil
	}
	fmt.Println("файлы целей в /data/input:")
	for i, j := range jobs {
		fmt.Printf("  %d) %s\n", i+1, j)
	}
	return jobs
}

func saveResults(path string, rows []portscan.Result) error {
	out := make([]resultOut, len(rows))
	for i, r := range rows {
		errText := ""
		if r.Err != nil {
			errText = r.Err.Error()
		}
		out[i] = resultOut{
			Host: r.Host, IP: r.IP.String(), Port: r.Port,
			State: r.State.String(), Duration: ms(r.Duration), ErrorText: errText,
		}
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

func listJobs() ([]string, error) {
	entries, err := os.ReadDir(inputDir)
	if err != nil {
		return nil, err
	}
	var jobs []string
	for _, e := range entries {
		name := e.Name()
		if !e.IsDir() && strings.HasSuffix(name, ".json") && !savedResultsName.MatchString(name) {
			jobs = append(jobs, name)
		}
	}
	return jobs, nil
}

func jobPath(line string, jobs []string) string {
	if line == "" {
		return ""
	}
	if n, err := strconv.Atoi(line); err == nil && n >= 1 && n <= len(jobs) {
		return filepath.Join(inputDir, jobs[n-1])
	}
	name := line
	if !strings.HasSuffix(name, ".json") {
		name += ".json"
	}
	for _, j := range jobs {
		if j == name {
			return filepath.Join(inputDir, name)
		}
	}
	return ""
}

func readJob(path string) (job, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return job{}, fmt.Errorf("не удалось прочитать файл: %w", err)
	}
	var j job
	if err := json.Unmarshal(data, &j); err != nil {
		return job{}, fmt.Errorf("некорректный JSON: %w", err)
	}
	if len(j.Hosts) == 0 {
		return job{}, errors.New("в файле нет списка hosts")
	}
	if len(j.Ports) == 0 {
		return job{}, errors.New("в файле нет списка ports")
	}
	return j, nil
}

// не показываем собственные сохраненные результаты в списке целей
var savedResultsName = regexp.MustCompile(`^results-\d{14}\.json$`)
