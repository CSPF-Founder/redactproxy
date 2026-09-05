package debuglog

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// DefaultMaxLogBytes is the default size threshold at which a
// RotatingWriter archives the current log file and starts a fresh one.
// "Full" tier logging carries real risk of unbounded growth (see
// debuglog's own package doc comment on why it logs real values at
// all): every request body it logs is the ENTIRE conversation history
// up to that point (the Messages API is stateless, so Claude Code re-
// sends everything on every turn), so a long session's total logged
// bytes grow roughly with the square of turn count, not linearly. 10
// MiB keeps any one part small enough to grep/inspect comfortably
// while still being large enough that routine chatty traffic doesn't
// rotate every few requests.
const DefaultMaxLogBytes int64 = 10 << 20 // 10 MiB

// RotatingWriter is an io.Writer that appends to a plain file at path
// until it reaches maxBytes, then archives the current file as a
// gzip-compressed part named for the moment of rotation (path +
// ".<timestamp>.gz") and continues writing to a fresh, empty file at
// path. Compression runs in the background so a large rotation doesn't
// stall the write that triggered it; the rename that hands the closed
// file off to the compression goroutine is the only synchronous
// rotation cost.
//
// Parts are named by timestamp rather than a persistent sequence
// number, the more common convention among mature log-rotation tools
// (e.g. lumberjack, logrotate's own dateext option) over the simpler
// but less standard incrementing-integer scheme. It sidesteps a whole
// class of question a counter raises: what should the next number be
// if an operator deletes a part mid-run, or deletes the highest-
// numbered one and then restarts the proxy? A number resumed by
// scanning the directory can end up reused for entirely different
// content across such a gap. A timestamp has no such ambiguity:
// deleting any archived part, at any time, has zero effect on what
// later parts get named, and the name itself tells a reviewer when
// that slice of traffic happened without cross-referencing file mtimes.
// No directory scan is needed at startup either, unlike the counter
// scheme this replaced.
//
// Safe for concurrent use; debuglog.Logger already serializes its own
// writes under one mutex, but RotatingWriter holds its own regardless
// so it's correct even used directly.
type RotatingWriter struct {
	mu       sync.Mutex
	path     string
	maxBytes int64
	f        *os.File
	size     int64
	archived sync.WaitGroup // in-flight background compressAndRemove calls -- see Close
}

// NewRotatingWriter opens (or resumes) a rotating log file at path.
// maxBytes <= 0 uses DefaultMaxLogBytes. Resuming means: if path
// already has content from a previous run, this appends to it rather
// than truncating, and rotates immediately if it's already at or past
// the threshold, so restarting redactproxy with debug logging still
// on never silently lets one file grow past the limit just because the
// size check didn't get a chance to run again until the next write.
func NewRotatingWriter(path string, maxBytes int64) (*RotatingWriter, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxLogBytes
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close() // returning the stat error; nothing to add
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	rw := &RotatingWriter{
		path:     path,
		maxBytes: maxBytes,
		f:        f,
		size:     info.Size(),
	}
	if rw.size >= rw.maxBytes {
		rw.mu.Lock()
		rw.rotateLocked()
		rw.mu.Unlock()
	}
	return rw, nil
}

// MaybeRotate checks the current file size and rotates now if it's at
// or past the threshold, the same check Write performs reactively
// after each write, exposed here for a caller (see
// debuglog.Logger.BeginRoundTrip) that wants rotation aligned to a
// logical boundary instead of whatever byte happened to cross the
// line. Also detects and recovers from the active file having been
// deleted out from under this writer; see reopenAfterDeletionLocked.
// Both checks run at the same, once-per-round-trip cadence rather than
// on every individual Write, deliberately: an extra stat(2) call on
// every full_sse_frame event (there can be hundreds in one streamed
// response) would be real, avoidable per-event overhead for something
// that only needs to be noticed within a round trip or so, not
// instantly.
func (rw *RotatingWriter) MaybeRotate() {
	rw.mu.Lock()
	defer rw.mu.Unlock()
	if rw.f == nil {
		return
	}
	if rw.activeFileGone() {
		rw.reopenAfterDeletionLocked()
		return
	}
	if rw.size >= rw.maxBytes {
		rw.rotateLocked()
	}
}

// activeFileGone reports whether rw.path no longer refers to a file on
// disk, i.e. whether it was deleted out from under the running proxy.
// A real scenario during a live engagement: an operator manually
// clearing disk space, or cleaning up debug output mid-session, exactly
// the kind of thing worth handling gracefully rather than either
// crashing or silently continuing to grow a now-invisible file. Checked
// by plain existence rather than an inode comparison; the latter needs
// POSIX-specific syscalls this writer would otherwise have no reason to
// depend on, and Windows doesn't generally allow deleting a file
// another process still has open in the first place, so there's no
// equivalent "unlinked while open" case to catch there.
func (rw *RotatingWriter) activeFileGone() bool {
	_, err := os.Stat(rw.path)
	return os.IsNotExist(err)
}

// reopenAfterDeletionLocked handles the active log file having been
// deleted: closes the now-orphaned handle (on Unix, a deleted-but-
// still-open file's storage isn't actually freed until every fd
// referencing it closes, so simply noticing the deletion isn't enough
// by itself, the proxy would otherwise keep growing an invisible file
// that no path points to) and opens a fresh file at the same path, so
// debug logging keeps working and stays visible rather than silently
// diverging from what `ls` shows. Content already written before the
// deletion is not recovered: once the directory entry is gone there's
// nothing left to rename or archive, and an operator deleting the file
// mid-run is choosing to discard it, the same as deleting any other
// file. Called with rw.mu held.
func (rw *RotatingWriter) reopenAfterDeletionLocked() {
	_ = rw.f.Close()
	f, err := os.OpenFile(rw.path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		rw.f = nil
		rw.size = 0
		return
	}
	rw.f = f
	rw.size = 0
}

func (rw *RotatingWriter) Write(p []byte) (int, error) {
	rw.mu.Lock()
	defer rw.mu.Unlock()
	if rw.f == nil {
		return 0, fmt.Errorf("debug log %s is unavailable (closed, or unavailable after a failed rotation)", rw.path)
	}
	n, err := rw.f.Write(p)
	rw.size += int64(n)
	if err == nil && rw.size >= rw.maxBytes {
		rw.rotateLocked()
	}
	return n, err
}

// rotateLocked closes the current file, hands it off (by path, via a
// synchronous rename so there's no window where two writers could see
// the same name) to a background goroutine for compression, and opens
// a fresh file at the original path. Called with rw.mu held.
func (rw *RotatingWriter) rotateLocked() {
	_ = rw.f.Close()
	rotatedPath := uniqueRotatedPath(rw.path)
	if err := os.Rename(rw.path, rotatedPath); err == nil {
		rw.archived.Go(func() { compressAndRemove(rotatedPath) })
	}
	// Best-effort beyond this point: if the file can't be reopened,
	// Write above starts returning an error, which is exactly what
	// debuglog.Logger.write already treats as "debug sink failed, drop
	// this event" (see its own doc comment) rather than something that
	// should ever affect request handling.
	f, err := os.OpenFile(rw.path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		rw.f = nil
		rw.size = 0
		return
	}
	rw.f = f
	rw.size = 0
}

// closeWaitTimeout bounds how long Close waits for in-flight background
// compressions to finish. A rotated part is capped at roughly maxBytes
// (10 MiB by default), and gzip.BestCompression on that little data
// takes well under a second on any real hardware, so this is generous
// headroom, not a tight budget; it exists purely so an unusually slow
// disk or a stuck goroutine can never hang process shutdown indefinitely.
const closeWaitTimeout = 5 * time.Second

// Close closes the currently-open file, then waits (briefly; see
// closeWaitTimeout) for any rotation already handed off to a background
// compression goroutine to finish, rather than abandoning it mid-flight.
// Without this, a normal shutdown (SIGTERM, the wizard restarting the
// proxy, even just Ctrl-C) that happens to land while a rotation is
// compressing leaves that part as an orphaned ".tmp" file plus its
// uncompressed source, neither harmful nor a data-loss risk (the
// uncompressed original is still complete and readable), but needless
// clutter on every shutdown that happens to catch a rotation mid-flight,
// which for a long, chatty engagement session is not a rare timing
// coincidence. Time-bounded rather than an unconditional wait so a
// stuck or unusually slow compression still can't block shutdown
// forever, matching this writer's overall best-effort posture (see
// compressAndRemove's own doc comment) at the process-exit boundary
// instead of the per-event one.
func (rw *RotatingWriter) Close() error {
	rw.mu.Lock()
	var closeErr error
	if rw.f != nil {
		closeErr = rw.f.Close()
		// Setting rw.f = nil here isn't just cleanup: Write and
		// MaybeRotate both already treat rw.f == nil as "unavailable,
		// do nothing" (see their own bodies), so this is what
		// guarantees no call still in flight when Close runs can reach
		// rotateLocked (and therefore rw.archived.Go, i.e. a new
		// WaitGroup.Add) after (or concurrently with) the Wait call
		// below. Without it, a slow in-flight request outliving
		// ServeHTTP's own shutdown grace period could call BeginRoundTrip
		// -> MaybeRotate -> rotateLocked concurrently with this Close,
		// racing an Add against a Wait that's already run to zero,
		// exactly the misuse sync.WaitGroup's own docs warn never to do.
		// (The exact race window is narrow enough that
		// TestRotatingWriter_CloseConcurrentWithLateWrites doesn't
		// reliably reproduce it under -race even across many runs; this
		// guard is correct by construction regardless; it can't make
		// any code path worse, and it removes the possibility outright
		// rather than relying on timing to avoid it.)
		rw.f = nil
	}
	rw.mu.Unlock()

	done := make(chan struct{})
	go func() {
		rw.archived.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(closeWaitTimeout):
	}
	return closeErr
}

// uniqueRotatedPath returns a not-currently-existing path to archive
// path's active content under, named for the moment of rotation; see
// RotatingWriter's doc comment for why timestamp-based rather than a
// persistent counter. Nanosecond precision with no colons (filesystem-
// unsafe on Windows, which this project cross-compiles for; see the
// Makefile's dist target) keeps two rotations of the same file from
// colliding in the overwhelming common case; rotateLocked only ever
// calls this while holding rw.mu, so back-to-back rotations are
// strictly serialized and separated by the real work rotateLocked does
// (closing a file, a rename, reopening); genuinely landing on the same
// nanosecond would need an unusually coarse system clock. The suffix
// loop below exists purely as a correctness backstop for that
// essentially-unreachable case, not as this scheme's actual uniqueness
// mechanism, so it doesn't need to be more elaborate than "keep trying
// the next integer."
func uniqueRotatedPath(path string) string {
	ts := time.Now().UTC().Format("20060102T150405.000000000Z")
	candidate := fmt.Sprintf("%s.%s", path, ts)
	for n := 2; ; n++ {
		if _, err := os.Stat(candidate); os.IsNotExist(err) {
			return candidate
		}
		candidate = fmt.Sprintf("%s.%s-%d", path, ts, n)
	}
}

// compressAndRemove gzips path into path+".gz" and removes path once
// that succeeds. Best-effort throughout: any failure leaves the
// uncompressed rotated file in place rather than losing it, since an
// uncompressed archived part is still strictly more useful than a
// deleted one.
//
// Writes to a ".tmp" name first and renames into place only once the
// gzip stream is fully closed and valid, rather than writing gzPath
// directly, so path+".gz" never exists on disk in a partial or
// corrupt state. Without this, a reader (an operator running `gunzip`
// the moment it appears, or this package's own tests polling for it)
// could observe the file mid-write and get a truncated archive; the
// rename makes its appearance atomic.
func compressAndRemove(path string) {
	in, err := os.Open(path)
	if err != nil {
		return
	}
	defer func() { _ = in.Close() }() // read-only; a close error says nothing

	gzPath := path + ".gz"
	tmpPath := gzPath + ".tmp"
	out, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	// BestCompression, not the package default (level 6): this runs in
	// a background goroutine off the request-handling hot path, so
	// there's no latency cost to spending more CPU on a better match
	// search within DEFLATE's fixed 32KB window. gzip.NewWriterLevel
	// only errors on an invalid level constant, which BestCompression
	// never is, so the error is deliberately not further handled beyond
	// aborting this archive attempt the same as any other step here.
	//
	// Every abandon path below discards its cleanup errors deliberately:
	// the archive is already being given up on for the error that got us
	// there, and the uncompressed original at path is untouched and still
	// complete, so the worst a failed cleanup leaves behind is a stray
	// .tmp file next to a log that is readable either way.
	gz, err := gzip.NewWriterLevel(out, gzip.BestCompression)
	if err != nil {
		_ = out.Close()
		_ = os.Remove(tmpPath)
		return
	}
	if _, err := io.Copy(gz, in); err != nil {
		_ = gz.Close()
		_ = out.Close()
		_ = os.Remove(tmpPath)
		return
	}
	// gz.Close and out.Close ARE checked: both flush buffered data, so an
	// error here means the archive on disk is short. Renaming it into
	// place anyway would replace a complete log with a truncated one.
	if err := gz.Close(); err != nil {
		_ = out.Close()
		_ = os.Remove(tmpPath)
		return
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return
	}
	if err := os.Rename(tmpPath, gzPath); err != nil {
		_ = os.Remove(tmpPath)
		return
	}
	_ = os.Remove(path)
}
