// Package fragment defines the core types shared between the detect engine
// and source implementations. It exists as a separate package to allow detect/
// to be imported without pulling in heavy source dependencies (archives, git).
package fragment

import (
	"context"

	"github.com/betterleaks/betterleaks/sources/scm"
)

// Fragment represents a fragment of a source with its meta data
type Fragment struct {
	// Raw is the raw content of the fragment
	Raw string

	Bytes []byte

	// FilePath is the path to the file if applicable.
	// The path separator MUST be normalized to `/`.
	FilePath    string
	SymlinkFile string
	// WindowsFilePath is the path with the original separator.
	// This provides a backwards-compatible solution to https://github.com/gitleaks/gitleaks/issues/1565.
	WindowsFilePath string `json:"-"` // TODO: remove this in v9.

	// CommitSHA is the SHA of the commit if applicable
	CommitSHA string // TODO: remove this in v9 and use CommitInfo instead

	// StartLine is the line number this fragment starts on
	StartLine int

	// CommitInfo captures additional information about the git commit if applicable
	CommitInfo *CommitInfo

	InheritedFromFinding bool // Indicates if this fragment is inherited from a finding
}

// CommitInfo contains metadata about a git commit.
type CommitInfo struct {
	AuthorEmail string
	AuthorName  string
	Date        string
	Message     string
	Remote      *RemoteInfo
	SHA         string
}

// RemoteInfo contains information about a git remote.
type RemoteInfo struct {
	Platform scm.Platform
	Url      string
}

// InnerPathSeparator is the separator used for paths inside archive files.
const InnerPathSeparator = "!"

// FragmentsFunc is the type of function called by Fragments to yield the next
// fragment.
type FragmentsFunc func(fragment Fragment, err error) error

// Source is a thing that can yield fragments.
type Source interface {
	// Fragments provides a filepath.WalkDir like interface for scanning the
	// fragments in the source.
	Fragments(ctx context.Context, yield FragmentsFunc) error
}
