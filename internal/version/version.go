// Package version holds the single source of truth for the OWNTRACE version.
package version

import "runtime"

// Version follows semantic versioning vMAJOR.MINOR.PATCH.
//
// 0.1.1 is the first patch release on top of the owner-designated 0.1.0
// initial release. It corrects finding-accounting and safety-coverage
// reporting only: persisted state counts are the single source of truth for
// every displayed total, and checks refused by the safety guards before
// execution are reported as safety-skipped instead of executed. No
// verification, confirmation or safety policy changed.
const Version = "0.1.1"

// Commit is injected at build time with -ldflags; "dev" in source builds.
var Commit = "dev"

// UserAgent is sent by OWNTRACE HTTP requests.
func UserAgent() string {
	return "OWNTRACE/" + Version + " (Automated Object Ownership & Authorization Testing)"
}

// String renders version and build metadata.
func String() string {
	return Version + " (" + Commit + ", " + runtime.GOOS + "/" + runtime.GOARCH + ", " + runtime.Version() + ")"
}
