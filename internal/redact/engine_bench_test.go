package redact

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CSPF-Founder/redactproxy/internal/tokenstore"
)

// benchEngine mirrors newCorpusEngine/newTypesEngine but takes b
// (testing.B also satisfies testing.TB) so it can live alongside the
// benchmarks without depending on the test-only helpers in other files.
func benchEngine(b *testing.B) *Engine {
	b.Helper()
	dir := b.TempDir()
	store, err := tokenstore.Open(filepath.Join(dir, "tokens.db"))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { store.Close() })
	return New(store, DefaultDetectors()...)
}

// realisticParagraph is one repeatable unit of pentest-report-shaped
// text mixing real PII (so detectors have genuine work to do, not just
// scan-and-reject) with large amounts of ordinary prose and code that no
// detector should match, the same balance a real tool_result/report
// dump has, not an artificially PII-dense corpus that would understate
// how much scanning is "wasted" on non-matching text in practice.
const realisticParagraph = `
Finding: SSRF on /fetch?url= allows internal requests to widgetcorp-fixture.com's
internal network (10.0.4.17). Confirmed via a callback to our own OOB listener at
4f2ab91c.burpcollaborator.net. The report script itself uses standard python-docx
calls: table = doc.add_table(rows=1, cols=4); table.style = 'Table Grid'. Admin
contact on file: admin@widgetcorp-fixture.com. A leaked AWS key was also found in
a .git dump: ` + awsKeyIDPrefix + `ABCD1234EFGH5678. Third-party assets on the page load normally
from cdn.jsdelivr.net/npm/vue and code.jquery.com/jquery-3.6.0.js, plus Google
Analytics via www.googletagmanager.com/gtag/js?id=G-ABCDE12345. None of that is
the client's own infrastructure. SSO tenant observed at widgetcorp-fixture.okta.com,
a real finding since the tenant name itself identifies the client. Nuclei scan
output showed nginx 1.22.1 flagged EOL across several hosts, cross-referenced
against endoflife.date and nginx.org for version context. No credentials were
found in this section of output, just ordinary tool banners and timing info like
"Request completed in 214ms" and "TTL 57, 4/4 packets received" repeated across
dozens of hosts during the sweep.
`

func buildBenchText(paragraphs int) string {
	var sb strings.Builder
	for range paragraphs {
		sb.WriteString(realisticParagraph)
	}
	return sb.String()
}

// benchmarkTokenizeSize runs Tokenize once per detection engine (fresh
// store each run, since GetOrCreateToken's cost differs for "new value"
// vs "already known": b.N reuses across iterations would silently shift
// from measuring cold-mint cost to warm-lookup cost partway through a
// run) against text built from n copies of realisticParagraph.
func benchmarkTokenizeSize(b *testing.B, paragraphs int) {
	text := buildBenchText(paragraphs)
	b.SetBytes(int64(len(text)))
	b.ResetTimer()
	for b.Loop() {
		e := benchEngine(b)
		if _, err := e.Tokenize(text); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTokenize_1Paragraph(b *testing.B)    { benchmarkTokenizeSize(b, 1) }
func BenchmarkTokenize_10Paragraphs(b *testing.B)  { benchmarkTokenizeSize(b, 10) }
func BenchmarkTokenize_100Paragraphs(b *testing.B) { benchmarkTokenizeSize(b, 100) }

// BenchmarkTokenize_NoMatches is the worst case for a per-detector full-
// text-scan architecture: every one of the ~37 detectors runs its full
// regex pass and finds nothing, so none of the "found something, do
// less work" shortcuts anywhere else in the pipeline (filterAllowed,
// resolveOverlaps, token minting) ever engage; this isolates pure
// detection-scanning cost from everything else Tokenize does.
func BenchmarkTokenize_NoMatches(b *testing.B) {
	var sb strings.Builder
	for range 100 {
		sb.WriteString("Ordinary prose with no PII, credentials, IPs, domains, or hashes of any kind. ")
		sb.WriteString("Just repeated English words to pad out the text to a realistic tool-output size. ")
	}
	text := sb.String()
	b.SetBytes(int64(len(text)))
	b.ResetTimer()
	for b.Loop() {
		e := benchEngine(b)
		if _, err := e.Tokenize(text); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkTokenize_RepeatedKnownValue measures the warm path: the same
// engine/store reused across iterations, tokenizing the identical
// realistic paragraph every time, so every value is already known after
// the first call (GetOrCreateToken hits its lookup path, not its mint
// path). This is the steady-state shape of a long-running engagement
// far more than the cold-mint benchmarks above are.
func BenchmarkTokenize_RepeatedKnownValue(b *testing.B) {
	e := benchEngine(b)
	text := buildBenchText(10)
	if _, err := e.Tokenize(text); err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(text)))
	b.ResetTimer()
	for b.Loop() {
		if _, err := e.Tokenize(text); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDetokenize_RepeatedKnownValue(b *testing.B) {
	e := benchEngine(b)
	text := buildBenchText(10)
	out, err := e.Tokenize(text)
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(out)))
	b.ResetTimer()
	for b.Loop() {
		e.Detokenize(out)
	}
}

func BenchmarkDetokenize_NoMatches(b *testing.B) {
	var sb strings.Builder
	for range 100 {
		sb.WriteString("Ordinary prose with no tokens, credentials, IPs, domains, or hashes of any kind. ")
		sb.WriteString("Just repeated English words to pad out the text to a realistic tool-output size. ")
	}
	text := sb.String()
	e := benchEngine(b)
	b.SetBytes(int64(len(text)))
	for b.Loop() {
		e.Detokenize(text)
	}
}

// BenchmarkTokenize_BurstOfNewValues measures the realistic "big recon
// dump" case: dozens of genuinely NEW distinct real values discovered in
// a single Tokenize call (e.g. a subfinder/dnsx/httpx output listing 40
// new subdomains at once). Isolates the token-minting/bbolt-write cost
// from the regex-scanning cost the other benchmarks measure, since every
// value here is new (never a store hit).
func BenchmarkTokenize_BurstOfNewValues(b *testing.B) {
	var sb strings.Builder
	for i := range 40 {
		fmt.Fprintf(&sb, "host burst-fixture-%d.example-target.com found, IP 10.%d.%d.%d\n", i, i/256, i%256, (i*7)%256)
	}
	text := sb.String()
	b.SetBytes(int64(len(text)))
	for b.Loop() {
		e := benchEngine(b)
		if _, err := e.Tokenize(text); err != nil {
			b.Fatal(err)
		}
	}
}
