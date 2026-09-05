package rules

import (
	"os"
	"time"
)

// Watcher polls a rules config file's mtime and calls onChange with the
// newly loaded Config whenever it changes (including the file being
// created after the watcher starts, or removed; a removed file reloads
// to an empty Config, not an error, matching Load's own "missing file
// isn't an error" contract).
//
// Polling instead of a filesystem-event library (fsnotify, inotify):
// this file changes at human-editing or CLI-subcommand speed, not a
// latency-sensitive hot path, so a 1-2 second poll is indistinguishable
// from "instant" to an operator while adding zero new dependencies.
type Watcher struct {
	path     string
	interval time.Duration
	onChange func(*Config)
	onError  func(error)
	lastMod  time.Time
	stop     chan struct{}
	done     chan struct{}
}

// NewWatcher builds a Watcher for path. It seeds its "last known mtime"
// from the file's current state (if it exists) at construction time, so
// the first poll after Start doesn't spuriously fire onChange for a file
// that hasn't actually changed since whoever constructed this already
// loaded it.
func NewWatcher(path string, interval time.Duration, onChange func(*Config), onError func(error)) *Watcher {
	w := &Watcher{
		path:     path,
		interval: interval,
		onChange: onChange,
		onError:  onError,
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
	if info, err := os.Stat(path); err == nil {
		w.lastMod = info.ModTime()
	}
	return w
}

// Start begins polling in the background. Call Stop to end it.
func (w *Watcher) Start() {
	go w.loop()
}

// Stop ends the polling goroutine and waits for it to exit.
func (w *Watcher) Stop() {
	close(w.stop)
	<-w.done
}

func (w *Watcher) loop() {
	defer close(w.done)
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		select {
		case <-w.stop:
			return
		case <-ticker.C:
			w.checkOnce()
		}
	}
}

func (w *Watcher) checkOnce() {
	info, err := os.Stat(w.path)
	if err != nil {
		if os.IsNotExist(err) {
			if !w.lastMod.IsZero() {
				// File existed, now doesn't; reload to the empty
				// config rather than leaving stale rules active.
				w.lastMod = time.Time{}
				w.onChange(&Config{})
			}
			return
		}
		if w.onError != nil {
			w.onError(err)
		}
		return
	}
	if info.ModTime().Equal(w.lastMod) {
		return
	}
	cfg, err := Load(w.path)
	if err != nil {
		// Deliberately does NOT update w.lastMod here. Save now writes
		// atomically (temp file + rename; see Config.Save), which
		// eliminates torn reads from this codebase's own writes, but
		// rules.json can also be hand-edited directly (see this
		// package's doc comment), and not every editor writes
		// atomically. If lastMod advanced unconditionally on a failed
		// read, the next poll would see "mtime already seen" and never
		// retry: the proxy would silently keep running whatever rules
		// it had before, even once the file settles into a fully valid
		// state. Leaving lastMod at its old value means the next poll
		// tick (one interval later) sees "current mtime != last known
		// good" again and retries automatically, self-healing within one
		// poll cycle instead of getting stuck indefinitely. See
		// TestWatcher_TornReadDuringWriteLeavesStaleRulesStuck.
		if w.onError != nil {
			w.onError(err)
		}
		return
	}
	w.lastMod = info.ModTime()
	w.onChange(cfg)
}
