package cfg

import (
	"regexp"
)

var (
	matchesRestEndpointRegexp = regexp.MustCompile(`^/v\d+/cas/[A-Za-z0-9_-]+$`)
	containsSlashRegex        = regexp.MustCompile(`/`)
)

func caIDInUnsupportedFormat(input string) bool {
	return matchesFullRestCasPattern(input) || containSlash(input)
}

func matchesFullRestCasPattern(input string) bool {
	return matchesRestEndpointRegexp.MatchString(input)
}

func containSlash(input string) bool {
	return containsSlashRegex.MatchString(input)
}
