package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestGracefulShutdown_InFlightRequestCompletesBeforeProcessExits verifies
// SIGTERM handling end to end against a REAL subprocess (signal.NotifyContext
// hooks real OS signals, which an in-process httptest.Server can't
// exercise). A slow fake upstream holds a request open; SIGTERM is sent
// to the real redactproxy binary while that request is still in flight;
// the request must still complete successfully (http.Server.Shutdown
// waits for in-flight requests), and the process must then exit cleanly
// within the shutdown timeout rather than hanging or being killed.
func TestGracefulShutdown_InFlightRequestCompletesBeforeProcessExits(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns a real subprocess and real OS signals; skip in -short")
	}

	bin := filepath.Join(t.TempDir(), "redactproxy_bin")
	build := exec.Command("go", "build", "-o", bin, "github.com/CSPF-Founder/redactproxy/cmd/redactproxy")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("build redactproxy: %v", err)
	}

	releaseUpstream := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-releaseUpstream // hold the request open until the test says go
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"id": "msg_1", "type": "message", "role": "assistant",
			"content": []map[string]any{{"type": "text", "text": "completed after shutdown signal"}},
		})
	}))
	defer upstream.Close()

	dataDir := t.TempDir()
	cmd := exec.Command(bin,
		"-engagement", "shutdown-test",
		"-data-dir", dataDir,
		"-listen", "127.0.0.1:0", // let the OS pick a free port; we'll parse it from the log
		"-upstream", upstream.URL,
	)
	// An explicit -engagement makes the proxy write a
	// .redactproxy-engagement marker into its working directory, which a
	// subprocess inherits from the test binary: without this it lands in
	// the package source tree.
	cmd.Dir = t.TempDir()
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })

	// Parse the listening address from the proxy's own startup log line
	// ("redactproxy listening" ... addr=...) rather than hardcoding a
	// port, since -listen 127.0.0.1:0 means the OS assigns one.
	addr := waitForListenAddr(t, stderrPipe)

	inFlightDone := make(chan string, 1)
	go func() {
		resp, err := http.Post("http://"+addr+"/v1/messages", "application/json", strings.NewReader(`{"messages":[{"role":"user","content":"hi"}]}`))
		if err != nil {
			inFlightDone <- "ERROR: " + err.Error()
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		inFlightDone <- string(body)
	}()

	// Give the request time to actually reach the upstream and be
	// genuinely in flight (blocked on releaseUpstream) before signaling.
	time.Sleep(200 * time.Millisecond)

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}

	// Let the in-flight request's upstream call finish shortly after the
	// signal, simulating a real slow-but-healthy agentic turn completing
	// during the shutdown grace period.
	time.Sleep(100 * time.Millisecond)
	close(releaseUpstream)

	select {
	case result := <-inFlightDone:
		if !strings.Contains(result, "completed after shutdown signal") {
			t.Fatalf("in-flight request did not complete successfully across SIGTERM: %s", result)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("in-flight request never completed -- SIGTERM should not abort it")
	}

	processExited := make(chan error, 1)
	go func() { processExited <- cmd.Wait() }()
	select {
	case err := <-processExited:
		if err != nil {
			t.Logf("process exited with: %v (fine -- SIGTERM exit status varies by platform)", err)
		}
	case <-time.After(12 * time.Second):
		t.Fatal("process did not exit within the graceful shutdown timeout")
	}
}

func waitForListenAddr(t *testing.T, r io.Reader) string {
	t.Helper()
	buf := make([]byte, 4096)
	var acc string
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		n, err := r.Read(buf)
		if n > 0 {
			acc += string(buf[:n])
			if idx := strings.Index(acc, "addr="); idx != -1 {
				rest := acc[idx+len("addr="):]
				end := strings.IndexAny(rest, " \n")
				if end == -1 {
					end = len(rest)
				}
				return rest[:end]
			}
		}
		if err != nil {
			break
		}
	}
	t.Fatal("timed out waiting for the proxy's listen address in its startup log")
	return ""
}
