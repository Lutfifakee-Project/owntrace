// Package version holds the single source of truth for the OWNTRACE version.
package version

import "runtime"

// Version follows semantic versioning vMAJOR.MINOR.PATCH.
//
// 0.1.0 is the FIRST complete product release, designated by the project
// owner (2026-11-21). The development lifecycle used internal milestone
// gates (v0.2.0–v1.0.0) for traceability; their artifacts remain preserved
// as history, and every mandatory capability ships in this initial release.
const Version = "0.1.0"

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
