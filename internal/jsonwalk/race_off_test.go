//go:build !race

package jsonwalk

// raceDetectorEnabled is false for a normal (non -race) test build. See
// race_on_test.go's counterpart for why perf_test.go needs to know this.
const raceDetectorEnabled = false
