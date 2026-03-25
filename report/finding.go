package report

import (
	"math"
	"strings"

	"github.com/betterleaks/betterleaks/fragment"
)

// Finding contains a whole bunch of information about a secret finding.
// Plenty of real estate in this bad boy so fillerup as needed.
type Finding struct {
	// Rule is the name of the rule that was matched
	RuleID      string
	Description string

	StartLine   int
	EndLine     int
	StartColumn int
	EndColumn   int

	Line string `json:"-"`

	Match string

	// Captured secret
	Secret string

	// CaptureGroups holds named regex capture groups from the match.
	CaptureGroups map[string]string `json:",omitempty"`

	// File is the name of the file containing the finding
	File        string
	SymlinkFile string
	Commit      string
	Link        string `json:",omitempty"`

	// Entropy is the shannon entropy of Value
	Entropy float32

	Author  string
	Email   string
	Date    string
	Message string
	Tags    []string

	// unique identifier
	Fingerprint string

	// MatchContext contains surrounding lines around the match
	MatchContext string `json:",omitempty"`

	// Fragment used for multi-part rule checking, CEL filtering,
	// and eventually ML validation
	Fragment *fragment.Fragment `json:",omitempty"`

	// RequiredSets holds the Cartesian-product combinations of required findings.
	// Each set is one complete group of components that can be validated independently.
	RequiredSets []RequiredSet `json:",omitempty"`

	ValidationStatus string         `json:",omitempty"`
	ValidationReason string         `json:",omitempty"`
	ValidationMeta   map[string]any `json:",omitempty"`
}

// RequiredSet represents one combination of required findings (one element per
// required rule) from the Cartesian product. Each set can be validated
// independently and carries its own validation result.
type RequiredSet struct {
	Components       []*RequiredFinding `json:"components"`
	ValidationStatus string             `json:"validationStatus,omitempty"`
	ValidationReason string             `json:"validationReason,omitempty"`
}

type RequiredFinding struct {
	// contains a subset of the Finding fields
	// only used for reporting
	RuleID           string
	StartLine        int
	EndLine          int
	StartColumn      int
	EndColumn        int
	Line             string `json:"-"`
	Match            string
	Secret           string
	CaptureGroups map[string]string `json:",omitempty"`
}

// BuildRequiredSets generates the Cartesian product of the given required findings
// grouped by RuleID and populates f.RequiredSets. maxRequiredSets caps the total number of
// combos to prevent excessive memory use.
func (f *Finding) BuildRequiredSets(requiredFindings []*RequiredFinding, maxRequiredSets int) {
	if len(requiredFindings) == 0 {
		f.RequiredSets = nil
		return
	}

	// Group by RuleID, preserving first-occurrence order.
	var ruleOrder []string
	byRule := make(map[string][]*RequiredFinding)
	for _, rf := range requiredFindings {
		if _, exists := byRule[rf.RuleID]; !exists {
			ruleOrder = append(ruleOrder, rf.RuleID)
		}
		byRule[rf.RuleID] = append(byRule[rf.RuleID], rf)
	}

	products := cartesianFindings(ruleOrder, byRule, maxRequiredSets)
	f.RequiredSets = make([]RequiredSet, len(products))
	for i, components := range products {
		f.RequiredSets[i] = RequiredSet{Components: components}
	}
}

// cartesianFindings computes the Cartesian product over RequiredFinding slices
// keyed by ruleOrder. It stops early once maxRequiredSets is reached.
func cartesianFindings(ruleOrder []string, byRule map[string][]*RequiredFinding, maxRequiredSets int) [][]*RequiredFinding {
	if len(ruleOrder) == 0 {
		return [][]*RequiredFinding{{}}
	}

	head := ruleOrder[0]
	rest := cartesianFindings(ruleOrder[1:], byRule, maxRequiredSets)

	var result [][]*RequiredFinding
	for _, rf := range byRule[head] {
		for _, tail := range rest {
			row := make([]*RequiredFinding, 0, len(tail)+1)
			row = append(row, rf)
			row = append(row, tail...)
			result = append(result, row)
			if len(result) >= maxRequiredSets {
				return result
			}
		}
	}
	return result
}

// Redact removes sensitive information from a finding.
func (f *Finding) Redact(percent uint) {
	secret := MaskSecret(f.Secret, percent)
	if percent >= 100 {
		secret = "REDACTED"
	}
	f.Line = strings.ReplaceAll(f.Line, f.Secret, secret)
	f.Match = strings.ReplaceAll(f.Match, f.Secret, secret)
	f.MatchContext = strings.ReplaceAll(f.MatchContext, f.Secret, secret)
	f.Secret = secret

	seen := make(map[*RequiredFinding]struct{})
	for _, set := range f.RequiredSets {
		for _, comp := range set.Components {
			if _, ok := seen[comp]; ok {
				continue
			}
			seen[comp] = struct{}{}
			compSecret := MaskSecret(comp.Secret, percent)
			if percent >= 100 {
				compSecret = "REDACTED"
			}
			comp.Match = strings.ReplaceAll(comp.Match, comp.Secret, compSecret)
			comp.Secret = compSecret
		}
	}
}

// MaskSecret applies partial masking to a secret string based on the given percentage.
// At 100% the caller should use "REDACTED" instead.
func MaskSecret(secret string, percent uint) string {
	if percent > 100 {
		percent = 100
	}
	len := float64(len(secret))
	if len <= 0 {
		return secret
	}
	prc := float64(100 - percent)
	lth := int64(math.RoundToEven(len * prc / float64(100)))

	return secret[:lth] + "..."
}

// PrintRequiredFindings, redactForDisplay, truncateSecret, and formatSetStatus
// are in display.go to keep lipgloss out of this file's import graph.
