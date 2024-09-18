package transport

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
)

type HostMatcher struct {
	suffixes []string
}

func NewHostMatcherFromFile(filepath string) (*HostMatcher, error) {
	f, err := os.Open(filepath)
	if err != nil {
		return nil, fmt.Errorf("could not open file: %w", err)
	}
	defer f.Close()

	suffixes := make([]string, 0)

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}

		log.Printf("add suffix: %s", line)
		suffixes = append(suffixes, line)
	}

	matcher := &HostMatcher{suffixes}
	return matcher, nil
}

func (m *HostMatcher) Matches(host string) bool {
	for _, suf := range m.suffixes {
		if strings.HasSuffix(host, suf) {
			log.Printf("host %s matches suffix %s", host, suf)
			return true
		}
	}
	return false
}
