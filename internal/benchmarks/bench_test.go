// Benchmarks for performance-critical components (spec section 9: measure
// before claiming performance characteristics).
package benchmarks_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/Lutfifakee-Project/owntrace/internal/config"
	"github.com/Lutfifakee-Project/owntrace/internal/endpoints"
	"github.com/Lutfifakee-Project/owntrace/internal/evidence"
	"github.com/Lutfifakee-Project/owntrace/internal/redact"
	"github.com/Lutfifakee-Project/owntrace/internal/scope"
	"github.com/Lutfifakee-Project/owntrace/internal/verification"
)

func BenchmarkRedactionSmallBody(b *testing.B) {
	body := []byte(`{"user":{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.abc","name":"alice"},"data":[1,2,3]}`)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = redact.BodyForEvidence("application/json", body)
	}
}

func BenchmarkRedactionLargeBody(b *testing.B) {
	item := []byte(`{"id":"o-1001","owner":"alice@example.com","secret":"s3cr3t-value-000000000000000000"},`)
	buf := make([]byte, 0, 64<<10)
	for len(buf) < (64<<10)-2 {
		buf = append(buf, item...)
	}
	buf = buf[:(64<<10)-2]
	body := append(append([]byte("["), buf...), ']')
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = redact.BodyForEvidence("application/json", body)
	}
}

func BenchmarkSimilarity64K(b *testing.B) {
	a := fmt.Sprintf("%s", bytes.Repeat([]byte(`{"k":"v","id":"o-1001"} `), 2600))
	bb := fmt.Sprintf("%s", bytes.Repeat([]byte(`{"k":"v","id":"o-1001"} `), 2600))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = verification.JaccardSimilarityForBenchmark(a, bb)
	}
}

func BenchmarkCanonicalJSONHash(b *testing.B) {
	data := map[string]any{"status": 200, "body": fmt.Sprintf("%s", bytes.Repeat([]byte("x"), 4096)),
		"headers": map[string]string{"A": "1", "B": "2"}}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		canon, err := evidence.CanonicalJSON(data)
		if err != nil {
			b.Fatal(err)
		}
		_ = sha256.Sum256(canon)
	}
}

func BenchmarkScopeCheck(b *testing.B) {
	sc, err := scope.New(config.Scope{
		Targets: []config.ScopeTarget{{Host: "api.example.com", IncludePaths: []string{"/api/"},
			ExcludePaths: []string{"/api/admin"}, AllowedMethods: []string{"GET"}}},
		GlobalAllowedMethods: []string{"GET"},
		BlockedPathPatterns:  config.DefaultBlockedPatterns(),
	})
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sc.Check("GET", "https://api.example.com/api/orders/1001")
	}
}

func BenchmarkEndpointBuild(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = endpoints.BuildFromURL("GET", "https://api.example.com/api/v1/orders/o-1001/notes", endpoints.SourceHAR, "bench")
	}
}

func BenchmarkJSONMarshalSorted(b *testing.B) {
	v := map[string]any{"z": 1, "a": map[string]any{"q": []int{3, 1, 2}, "b": "x"}, "m": []string{"p", "o"}}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = json.Marshal(v)
	}
}
