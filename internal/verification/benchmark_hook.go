// Exported test/benchmark hooks: production code must not use these.
package verification

// JaccardSimilarityForBenchmark exposes the similarity heuristic for the
// performance benchmarks without widening its usage elsewhere.
func JaccardSimilarityForBenchmark(a, b string) float64 {
	return jaccardSimilarity(a, b)
}
