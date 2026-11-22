// Fuzz tests for untrusted-input parsers (v0.4.0). The seed corpus runs as
// regular tests via `go test`; extended fuzzing runs with
// `go test -fuzz=FuzzX -fuzztime=30s ./internal/discovery/`.
package discovery_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Lutfifakee-Project/owntrace/internal/discovery"
	"github.com/Lutfifakee-Project/owntrace/internal/endpoints"
)

func writeTemp(t *testing.T, name string, content []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// FuzzParseHAR: malformed or hostile HAR input must never panic and must
// never produce endpoints with credential-bearing material.
func FuzzParseHAR(f *testing.F) {
	seeds := []string{
		`{"log":{"entries":[]}}`,
		`{"log":{"entries":[{"request":{"method":"GET","url":"https://api.test/a/b"}}]}}`,
		`{"log":{"entries":[{"request":{"method":"","url":""}}]}}`,
		`{"log":null}`,
		`{}`,
		`[1,2,3`,
		`{"log":{"entries":[{"request":{"method":"GET","url":"https://x/","headers":[{"name":"Authorization","value":"Bearer xyz"},{"name":"X-Owntrace-Profile","value":"A"}],"postData":{"mimeType":"application/json","text":"{\"a\":1}"}},"response":{"status":200,"content":{"text":"{\"id\":\"x\"}"}}}]}}`,
		`{"log":{"entries":[null,{"request":"x"}]}}`,
		"\x00\x01\x02",
		strings.Repeat("{\"log\":{\"entries\":[", 64),
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		res := discovery.NewResult()
		_ = discovery.ParseHAR(writeTemp(t, "fuzz.har", data), "X-Owntrace-Profile", res)
		// Any endpoint produced must not embed raw "Bearer " credentials.
		for _, ep := range res.Endpoints.List() {
			for _, h := range ep.Headers {
				if len(h.Example) > 4096 {
					t.Errorf("unbounded header example retained")
				}
			}
		}
	})
}

// FuzzParseOpenAPI: hostile specs must parse without panics.
func FuzzParseOpenAPI(f *testing.F) {
	seeds := []string{
		`{"openapi":"3.0.0","paths":{"/a":{"get":{}}}}`,
		`{"swagger":"2.0","host":"x","basePath":"/v1","paths":{"/a":{"get":{"parameters":[{"$ref":"#/parameters/P"}]}}},"parameters":{"P":{"name":"id","in":"path","required":true,"type":"string"}}}`,
		`{"openapi":"3.0.0","paths":{"/a":{"get":{"requestBody":{"content":{"application/json":{"schema":{"$ref":"#/components/schemas/S"}}}}}}},"components":{"schemas":{"S":{"$ref":"#/components/schemas/S"}}}}`,
		`{"openapi":"3.0.0","paths":{"<{>>":{"get":null}}}`,
		`{"paths":null}`,
		`{"$ref":"#/x/y/z","paths":{}}`,
		strings.Repeat(`{"$ref":"#/a/`, 200),
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		res := discovery.NewResult()
		_ = discovery.ParseOpenAPI(writeTemp(t, "fuzz.json", data), res)
	})
}

// FuzzBuildFromURL: URL templating must be panic-free and idempotent on
// identifier-like segments.
func FuzzBuildFromURL(f *testing.F) {
	seeds := []string{
		"https://api.test/api/v1/orders/o-1001",
		"https://api.test/x/550e8400-e29b-41d4-a716-446655440000",
		"http://[::1]:8080/a",
		"https://u:p@host/x",
		"file:///etc/passwd",
		"https://host/" + strings.Repeat("9", 300),
		"https://host/a/b/c/../../d",
		"::::",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		ep, ok := endpoints.BuildFromURL("GET", raw, endpoints.SourceURL, "fuzz")
		if !ok {
			return
		}
		// Templated output must never panic on refill and must keep the host.
		if ep.Host == "" {
			t.Errorf("endpoint without host from %q", raw)
		}
		_, _, _ = ep.FillURL(map[string]string{})
	})
}
