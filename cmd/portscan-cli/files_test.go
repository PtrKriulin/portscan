package main

import (
	"testing"
)

func TestIsYes(t *testing.T) {
	for _, s := range []string{"y", "Y", "yes", "YES", "да", "Да", "ДА"} {
		if !isYes(s) {
			t.Errorf("isYes(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"", "n", "no", "нет", "yeee"} {
		if isYes(s) {
			t.Errorf("isYes(%q) = true, want false", s)
		}
	}
}

func TestJobPath(t *testing.T) {
	jobs := []string{"job.json", "other.json"}
	cases := []struct {
		in   string
		want string
	}{
		{"1", "/data/input/job.json"},
		{"2", "/data/input/other.json"},
		{"job.json", "/data/input/job.json"},
		{"job", "/data/input/job.json"}, // суффикс .json опускается
		{"3", ""},                       // нет такого номера
		{"unknown", ""},                 // нет такого файла
		{"", ""},                        // пустой ввод
		{"job.json.txt", ""},            // не из списка
	}
	for _, tc := range cases {
		if got := jobPath(tc.in, jobs); got != tc.want {
			t.Errorf("jobPath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestSavedResultsName(t *testing.T) {
	for _, s := range []string{"results-20261029132318.json", "results-20000101000000.json"} {
		if !savedResultsName.MatchString(s) {
			t.Errorf("%q must be recognized as a saved result", s)
		}
	}
	for _, s := range []string{"results.json", "results_my_targets.json", "results-20261029.json", "results-2026102913231.json"} {
		if savedResultsName.MatchString(s) {
			t.Errorf("%q must not be recognized as a saved result", s)
		}
	}
}
