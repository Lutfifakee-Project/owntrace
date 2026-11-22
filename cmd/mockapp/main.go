// mockapp cmd runs the vulnerable laboratory application for manual testing.
package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/Lutfifakee-Project/owntrace/internal/mockapp"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8099", "listen address")
	flag.Parse()
	app := mockapp.New()
	fmt.Fprintln(os.Stderr, "⚠  OWNTRACE laboratory app: deliberately vulnerable — bind to loopback only, never expose.")
	fmt.Fprintf(os.Stderr, "   users: alice/pw-alice  bob/pw-bob  admin/pw-admin (POST /api/v1/login)\n")
	if err := http.ListenAndServe(*addr, app.Handler()); err != nil {
		fmt.Fprintln(os.Stderr, "listen:", err)
		os.Exit(1)
	}
}
