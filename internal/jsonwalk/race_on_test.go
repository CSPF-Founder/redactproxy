//go:build race

package jsonwalk

// raceDetectorEnabled is true when this test binary was built with
// `go test -race`. Race instrumentation adds heavy per-memory-access
// overhead, so a performance regression guard's budget needs to scale
// with it separately from what actually distinguishes a genuine
// algorithmic regression -- see perf_test.go's use of this.
const raceDetectorEnabled = true
