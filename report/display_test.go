package report

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test_locateMatch verifies the near-position fallback logic that
// disambiguates duplicate occurrences of the same match on a line.
func Test_locateMatch(t *testing.T) {
	tests := map[string]struct {
		rawLine  string
		rawMatch string
		startCol int
		want     int
	}{
		"empty line": {
			rawLine:  "",
			rawMatch: "abc",
			startCol: 1,
			want:     -1,
		},
		"empty match": {
			rawLine:  "abc",
			rawMatch: "",
			startCol: 1,
			want:     -1,
		},
		"exact position hit": {
			rawLine:  "prefix key=SECRET suffix",
			rawMatch: "key=SECRET",
			startCol: 8, // byte 7 is 'k', 1-indexed = 8
			want:     7,
		},
		"first of duplicates via startCol": {
			rawLine:  "tok tok",
			rawMatch: "tok",
			startCol: 1,
			want:     0,
		},
		"second of duplicates via startCol": {
			rawLine:  "tok tok",
			rawMatch: "tok",
			startCol: 5,
			want:     4,
		},
		"startCol slightly off - forward search finds nearer": {
			// startCol points 1 byte before the second "tok"
			rawLine:  "tok ...tok",
			rawMatch: "tok",
			startCol: 7, // byte 6, actual second "tok" is at byte 7
			want:     7, // forward search from byte 6 finds byte 7
		},
		"startCol past match - backward search finds it": {
			rawLine:  "abc SECRET def",
			rawMatch: "SECRET",
			startCol: 14, // past end of "SECRET"
			want:     4,  // backward search from byte 13 finds byte 4
		},
		"no startCol falls back to strings.Index": {
			rawLine:  "tok tok",
			rawMatch: "tok",
			startCol: 0,
			want:     0, // first occurrence
		},
		"match not in line": {
			rawLine:  "no match here",
			rawMatch: "SECRET",
			startCol: 1,
			want:     -1,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := locateMatch(tt.rawLine, tt.rawMatch, tt.startCol)
			assert.Equal(t, tt.want, got)
		})
	}
}
