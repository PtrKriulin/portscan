package main

import (
	"strings"
	"testing"
)

func TestSplitValues(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"22, 33, ,44", []string{"22", "33", "44"}},
		{"22", []string{"22"}},
		{"", nil},
		{", , ", nil},
		{"a,b ,  c", []string{"a", "b", "c"}},
	}
	for _, tc := range cases {
		got := splitValues(tc.in)
		if strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Errorf("splitValues(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestParsePortSpecs(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		wantErr bool
		wantLen int
	}{
		{"mixed", "22, 80, 8000-9000", false, 3},
		{"single", "22", false, 1},
		{"only range", "8000-9000", false, 1},
		{"empty", "", false, 0}, // пустая строка — пустой список спек, валидация пакета решит
		{"bad token", "22, abc", true, 0},
		{"bad range", "80-x", true, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			specs, err := parsePortSpecs(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("parsePortSpecs(%q) err = %v, wantErr = %v", tc.in, err, tc.wantErr)
			}
			if len(specs) != tc.wantLen {
				t.Fatalf("parsePortSpecs(%q) = %d specs, want %d", tc.in, len(specs), tc.wantLen)
			}
		})
	}
}
