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
		{"job", "/data/input/job.json"}, // суффикс дописывается, если нет
		{"3", ""},
		{"unknown", ""},
		{"", ""},
		{"job.json.txt", ""},
	}
	for _, tc := range cases {
		if got := jobPath(tc.in, jobs); got != tc.want {
			t.Errorf("jobPath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
