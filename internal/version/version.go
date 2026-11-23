// Package version holds the single source of truth for the OWNTRACE version.
package version

import "runtime"

// Version follows semantic versioning vMAJOR.MINOR.PATCH.
//
// 0.1.2 is an installation-experience and documentation release: the primary
// installation path is a single `go install .../cmd/owntrace@latest` command
// with corrected toolchain and PATH guidance, and the public product identity
// is aligned to "Automated IDOR/BOLA Pentesting Tool". No verification,
// confirmation, safety policy or dependency changed.
const Version = "0.1.2"

// Commit is injected at build time with -ldflags; "dev" in source builds.
var Commit = "dev"

// UserAgent is sent by OWNTRACE HTTP requests.
func UserAgent() string {
	return "OWNTRACE/" + Version + " (Automated IDOR/BOLA Pentesting Tool)"
}

// String renders version and build metadata.
func String() string {
	return Version + " (" + Commit + ", " + runtime.GOOS + "/" + runtime.GOARCH + ", " + runtime.Version() + ")"
}
