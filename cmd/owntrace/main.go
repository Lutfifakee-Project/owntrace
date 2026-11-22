// OWNTRACE — Automated Object Ownership & Authorization Testing.
//
// This binary is a thin entrypoint; all behavior lives in internal/cli.
package main

import (
	"os"

	"github.com/Lutfifakee-Project/owntrace/internal/cli"
)

func main() {
	os.Exit(cli.Main(os.Args[1:], os.Stdout, os.Stderr))
}
