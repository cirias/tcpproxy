
package transport

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestHostMatcher_Matches(t *testing.T) {
	testCases := []struct {
		name     string
		suffixes []string
		host     string
		want     bool
	}{
		{
			name:     "exact match",
			suffixes: []string{"example.com"},
			host:     "example.com",
			want:     true,
		},
		{
			name:     "subdomain match with dot prefix",
			suffixes: []string{".example.com"},
			host:     "sub.example.com",
			want:     true,
		},
		{
			name:     "subdomain match without dot prefix",
			suffixes: []string{"example.com"},
			host:     "sub.example.com",
			want:     true,
		},
		{
			name:     "no match",
			suffixes: []string{".google.com"},
			host:     "sub.example.com",
			want:     false,
		},
		{
			name:     "partial match is not a suffix match",
			suffixes: []string{"example"},
			host:     "example.com",
			want:     false,
		},
		{
			name:     "multiple suffixes, first matches",
			suffixes: []string{".example.com", ".google.com"},
			host:     "sub.example.com",
			want:     true,
		},
		{
			name:     "multiple suffixes, second matches",
			suffixes: []string{".google.com", ".example.com"},
			host:     "sub.example.com",
			want:     true,
		},
		{
			name:     "empty host",
			suffixes: []string{".example.com"},
			host:     "",
			want:     false,
		},
		{
			name:     "empty suffixes",
			suffixes: []string{},
			host:     "example.com",
			want:     false,
		},
		{
			name:     "mismatch where host is shorter",
			suffixes: []string{".example.com"},
			host:     "example.co",
			want:     false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			m := &HostMatcher{suffixes: tc.suffixes}
			if got := m.Matches(tc.host); got != tc.want {
				t.Errorf("HostMatcher.Matches(%q) = %v, want %v", tc.host, got, tc.want)
			}
		})
	}
}

func TestNewHostMatcherFromFile(t *testing.T) {
	t.Run("valid file", func(t *testing.T) {
		content := `
# This is a comment
.example.com
  
  .google.com
localhost
`
		tmpfile := filepath.Join(t.TempDir(), "hosts.txt")
		if err := os.WriteFile(tmpfile, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to write temp file: %v", err)
		}

		matcher, err := NewHostMatcherFromFile(tmpfile)
		if err != nil {
			t.Fatalf("NewHostMatcherFromFile() error = %v, wantErr %v", err, false)
		}

		wantSuffixes := []string{".example.com", ".google.com", "localhost"}
		if !reflect.DeepEqual(matcher.suffixes, wantSuffixes) {
			t.Errorf("NewHostMatcherFromFile() got suffixes = %v, want %v", matcher.suffixes, wantSuffixes)
		}
	})

	t.Run("file not found", func(t *testing.T) {
		_, err := NewHostMatcherFromFile("nonexistent-file.txt")
		if err == nil {
			t.Errorf("NewHostMatcherFromFile() error = nil, want an error for non-existent file")
		}
	})
}
