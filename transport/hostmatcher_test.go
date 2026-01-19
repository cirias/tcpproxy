package transport

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHostMatcherMatches(t *testing.T) {
	dir := t.TempDir()
	suffixFile := filepath.Join(dir, "suffixes.txt")
	contents := strings.Join([]string{
		"# comment",
		"  .example.com  ",
		"",
		"foo.bar",
		"# another",
	}, "\n")
	if err := os.WriteFile(suffixFile, []byte(contents), 0o600); err != nil {
		t.Fatalf("write suffixes file: %v", err)
	}

	matcher, err := NewHostMatcherFromFile(suffixFile)
	if err != nil {
		t.Fatalf("create matcher: %v", err)
	}

	tests := []struct {
		host string
		want bool
	}{
		{host: "api.example.com", want: true},
		{host: "example.com", want: false},
		{host: "foo.bar", want: true},
		{host: "myfoo.bar", want: true},
		{host: "bar", want: false},
		{host: "example.org", want: false},
	}

	for _, tc := range tests {
		if got := matcher.Matches(tc.host); got != tc.want {
			t.Fatalf("Matches(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

func TestHostMatcherMatchesEmptyFile(t *testing.T) {
	dir := t.TempDir()
	suffixFile := filepath.Join(dir, "suffixes.txt")
	contents := strings.Join([]string{
		"# comment",
		"",
		"   ",
		"# another",
	}, "\n")
	if err := os.WriteFile(suffixFile, []byte(contents), 0o600); err != nil {
		t.Fatalf("write suffixes file: %v", err)
	}

	matcher, err := NewHostMatcherFromFile(suffixFile)
	if err != nil {
		t.Fatalf("create matcher: %v", err)
	}

	if matcher.Matches("example.com") {
		t.Fatalf("Matches(%q) = true, want false", "example.com")
	}
}
