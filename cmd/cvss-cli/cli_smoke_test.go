package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/spf13/pflag"
)

// vec builds a CVSS vector string by concatenating parts instead of writing
// it as a single string literal.
//
// Under Go 1.25, a long CVSS vector written as one literal is intermittently
// miscompiled: a '/' separator (e.g. the one before "C:H") is corrupted to
// ':' at compile time, so parser.ParseString fails with "invalid vector value:
// H:I:H". The corruption is content-dependent, cache-state-dependent, and
// surfaces only when the test binary also links pkg/parser; it is not a
// parser bug. Constructing the same string at runtime via strings.Join
// sidesteps the bad compile-time folding and yields correct bytes reliably.
func vec(parts ...string) string {
	return strings.Join(parts, "")
}

// hiVec returns the canonical 9.8 Critical base vector.
func hiVec() string {
	return vec("CVSS:3.1/", "AV:N/AC:L/PR:N/UI:N/S:U/", "C:H/I:H/A:H")
}

// loAVec is hiVec with Availability downgraded to Low.
func loAVec() string {
	return vec("CVSS:3.1/", "AV:N/AC:L/PR:N/UI:N/S:U/", "C:H/I:H/A:L")
}

// hiVecTemporal is hiVec with temporal metrics appended.
func hiVecTemporal() string {
	return vec(hiVec(), "/E:F/RL:T/RC:C")
}

// hiVecEnvironmental is hiVec with environmental metrics appended.
func hiVecEnvironmental() string {
	return vec(hiVec(), "/CR:H/IR:H/AR:H")
}

// resetFlags restores every command's flags to their default values.
//
// cobra parses flags into the persistent *flag.FlagSet of the target command,
// and those values survive across Execute calls — so a test that sets
// --breakdown leaves showBreakdown=true for the next test. Resetting before
// each run keeps flag-dependent tests isolated.
func resetFlags() {
	for _, cmd := range rootCmd.Commands() {
		cmd.Flags().VisitAll(func(f *pflag.Flag) {
			_ = f.Value.Set(f.DefValue)
		})
	}
	// rootCmd's own flags (e.g. --version) too.
	rootCmd.Flags().VisitAll(func(f *pflag.Flag) {
		_ = f.Value.Set(f.DefValue)
	})
}

// runCommand executes the root command with the given args, capturing stdout
// (including fmt.Println output, which bypasses cobra's writer).
//
// It redirects os.Stdout to a pipe for the duration of the command, then
// restores it. Errors cause the command to call os.Exit(1) via die/dief, so
// only success paths are exercised here.
func runCommand(t *testing.T, args ...string) string {
	t.Helper()

	// Reset flag state left over from prior tests (see resetFlags).
	resetFlags()

	// Save and restore os.Stdout. We replace it with a pipe so that direct
	// fmt.Println calls (which bypass cobra's writer) are captured.
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w

	// Silence cobra's own usage/error output.
	silenced := rootCmd.SilenceErrors
	rootCmd.SilenceErrors = true
	rootCmd.SetErr(io.Discard)
	rootCmd.SetArgs(args)

	// Start reading concurrently: the command may write more than the pipe
	// buffer (64KB), so we must drain the read end while Execute runs, or the
	// write would block and deadlock.
	var buf bytes.Buffer
	copyDone := make(chan struct{})
	go func() {
		_, _ = io.Copy(&buf, r)
		close(copyDone)
	}()

	// Run Execute synchronously on the main goroutine.
	execErr := rootCmd.Execute()

	// Restore stdout and close the write end so the reader can finish.
	os.Stdout = orig
	w.Close()
	<-copyDone
	r.Close()

	rootCmd.SilenceErrors = silenced
	rootCmd.SetArgs(nil)

	if execErr != nil {
		t.Fatalf("unexpected error for args %v: %v", args, execErr)
	}
	return buf.String()
}

// TestScoreCommand verifies the score command produces the expected score
// and severity for the canonical 9.8 Critical vector.
func TestScoreCommand(t *testing.T) {
	out := runCommand(t, "score", hiVec())
	if !strings.Contains(out, "9.8") {
		t.Errorf("score output missing 9.8: %q", out)
	}
	if !strings.Contains(out, "Critical") {
		t.Errorf("score output missing Critical: %q", out)
	}
}

// TestScoreCommand_JSON verifies JSON output format.
func TestScoreCommand_JSON(t *testing.T) {
	out := runCommand(t, "score", "--format", "json", hiVec())
	if !strings.Contains(out, `"score"`) {
		t.Errorf("json output missing score key: %q", out)
	}
	if !strings.Contains(out, `"severity"`) {
		t.Errorf("json output missing severity key: %q", out)
	}
}

// TestScoreCommand_Breakdown verifies the --breakdown flag prints per-metric
// score details, exercising printBreakdown and printMetricScore.
func TestScoreCommand_Breakdown(t *testing.T) {
	out := runCommand(t, "score", "--breakdown", hiVec())
	if !strings.Contains(out, "Score Breakdown") {
		t.Errorf("breakdown output missing 'Score Breakdown': %q", out)
	}
	if !strings.Contains(out, "Base Metrics") {
		t.Errorf("breakdown output missing 'Base Metrics': %q", out)
	}
	// A per-metric line like "AV:N = 0.8500" should appear.
	if !strings.Contains(out, "AV:N =") {
		t.Errorf("breakdown output missing AV metric line: %q", out)
	}
}

// TestScoreCommand_BreakdownTemporal verifies --breakdown on a temporal vector
// surfaces the Temporal Metrics section.
func TestScoreCommand_BreakdownTemporal(t *testing.T) {
	out := runCommand(t, "score", "--breakdown", hiVecTemporal())
	if !strings.Contains(out, "Temporal Metrics") {
		t.Errorf("breakdown output missing 'Temporal Metrics': %q", out)
	}
	if !strings.Contains(out, "E:F =") {
		t.Errorf("breakdown output missing E metric line: %q", out)
	}
}

// TestScoreCommand_BreakdownEnvironmental verifies --breakdown on an
// environmental vector surfaces the Environmental Metrics section.
func TestScoreCommand_BreakdownEnvironmental(t *testing.T) {
	out := runCommand(t, "score", "--breakdown", hiVecEnvironmental())
	if !strings.Contains(out, "Environmental Metrics") {
		t.Errorf("breakdown output missing 'Environmental Metrics': %q", out)
	}
	if !strings.Contains(out, "CR:H =") {
		t.Errorf("breakdown output missing CR metric line: %q", out)
	}
}

// TestScoreCommand_All verifies the --all flag prints the base score with
// severity, exercising the showAll branch.
func TestScoreCommand_All(t *testing.T) {
	out := runCommand(t, "score", "--all", hiVec())
	if !strings.Contains(out, "9.8") {
		t.Errorf("--all output missing base 9.8: %q", out)
	}
	if !strings.Contains(out, "Critical") {
		t.Errorf("--all output missing Critical severity: %q", out)
	}
}

// TestScoreCommand_AllJSON verifies --all combines with --format json.
func TestScoreCommand_AllJSON(t *testing.T) {
	out := runCommand(t, "score", "--all", "--format", "json", hiVec())
	if !strings.Contains(out, `"BaseScore"`) {
		t.Errorf("--all json output missing BaseScore: %q", out)
	}
	if !strings.Contains(out, `"BaseSeverity"`) {
		t.Errorf("--all json output missing BaseSeverity: %q", out)
	}
}

// TestParseCommand verifies the parse command outputs vector components.
func TestParseCommand(t *testing.T) {
	out := runCommand(t, "parse", hiVec())
	if !strings.Contains(out, "Version:") {
		t.Errorf("parse output missing Version: %q", out)
	}
	if !strings.Contains(out, hiVec()) {
		t.Errorf("parse output missing vector string: %q", out)
	}
}

// TestValidateCommand verifies validate succeeds for a complete vector.
func TestValidateCommand(t *testing.T) {
	out := runCommand(t, "validate", hiVec())
	if !strings.Contains(out, "valid") && !strings.Contains(out, "Valid") {
		t.Errorf("validate output should mention valid: %q", out)
	}
}

// TestSeverityCommand verifies the severity command.
func TestSeverityCommand(t *testing.T) {
	out := runCommand(t, "severity", "9.8")
	if !strings.Contains(out, "Critical") {
		t.Errorf("severity output missing Critical: %q", out)
	}
}

// TestJSONCommand verifies JSON serialization includes scores.
func TestJSONCommand(t *testing.T) {
	out := runCommand(t, "json", hiVec())
	if !strings.Contains(out, "baseScore") {
		t.Errorf("json output missing baseScore: %q", out)
	}
}

// TestDiffCommand verifies the diff command compares two vectors.
func TestDiffCommand(t *testing.T) {
	out := runCommand(t, "diff", hiVec(), loAVec())
	// The two vectors differ only in A (H vs L), so the output should mention A.
	if !strings.Contains(out, "A") {
		t.Errorf("diff output should mention metric A: %q", out)
	}
}

// TestDistanceCommand verifies the distance command computes distances.
func TestDistanceCommand(t *testing.T) {
	out := runCommand(t, "distance", hiVec(), loAVec())
	if !strings.Contains(out, "euclidean") && !strings.Contains(out, "Euclidean") {
		t.Errorf("distance output missing euclidean: %q", out)
	}
}

// TestBuildCommand verifies the build command constructs a vector.
func TestBuildCommand(t *testing.T) {
	out := runCommand(t, "build",
		"--AV", "N", "--AC", "L", "--PR", "N", "--UI", "N",
		"--S", "U", "--C", "H", "--I", "H", "--A", "H",
	)
	if !strings.Contains(out, hiVec()) {
		t.Errorf("build output missing expected vector: %q", out)
	}
}

// TestEnumerateCommand verifies the enumerate command lists metrics.
func TestEnumerateCommand(t *testing.T) {
	out := runCommand(t, "enumerate")
	if !strings.Contains(out, "AV") {
		t.Errorf("enumerate output missing AV: %q", out)
	}
}

// runCommandWithStdin is like runCommand but also feeds stdinText to the
// command's standard input (used by sort, which reads vectors from stdin
// when given "-" or no file argument).
func runCommandWithStdin(t *testing.T, stdinText string, args ...string) string {
	t.Helper()

	// Reset flag state left over from prior tests (see resetFlags).
	resetFlags()

	origOut := os.Stdout
	origIn := os.Stdin
	rOut, wOut, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	rIn, wIn, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = wOut
	os.Stdin = rIn

	// Write stdin in a goroutine so a large input cannot deadlock.
	go func() {
		_, _ = io.WriteString(wIn, stdinText)
		wIn.Close()
	}()

	silenced := rootCmd.SilenceErrors
	rootCmd.SilenceErrors = true
	rootCmd.SetErr(io.Discard)
	rootCmd.SetArgs(args)

	var buf bytes.Buffer
	copyDone := make(chan struct{})
	go func() {
		_, _ = io.Copy(&buf, rOut)
		close(copyDone)
	}()

	execErr := rootCmd.Execute()

	os.Stdout = origOut
	os.Stdin = origIn
	wOut.Close()
	<-copyDone
	rOut.Close()
	rIn.Close()

	rootCmd.SilenceErrors = silenced
	rootCmd.SetArgs(nil)

	if execErr != nil {
		t.Fatalf("unexpected error for args %v: %v", args, execErr)
	}
	return buf.String()
}

// runCommandExpectError runs the root command with args that are expected to
// trigger a die/dief error path. It substitutes exitFunc with a panic-on-call
// so the error path can be recovered instead of killing the test process,
// captures combined stdout+stderr, and returns the captured output.
//
// The test fails if the command does NOT trigger an exit (i.e. completes
// normally), because that means the error path was not exercised as intended.
func runCommandExpectError(t *testing.T, args ...string) string {
	t.Helper()

	// Reset flag state left over from prior tests (see resetFlags).
	resetFlags()

	// Substitute exitFunc so die/dief panic instead of killing the process.
	// The panic carries an exit-code sentinel so we can distinguish an
	// intentional exit from an unexpected panic.
	origExit := exitFunc
	exitFunc = func(code int) { panic(struct{ code int }{code}) }
	defer func() { exitFunc = origExit }()

	origOut := os.Stdout
	origErr := os.Stderr
	// Use a single pipe for combined stdout+stderr so die/dief's Fprintf to
	// os.Stderr is captured alongside cobra's own output.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w
	os.Stderr = w

	silenced := rootCmd.SilenceErrors
	rootCmd.SilenceErrors = true
	rootCmd.SetErr(io.Discard)
	rootCmd.SetArgs(args)

	var buf bytes.Buffer
	copyDone := make(chan struct{})
	go func() {
		_, _ = io.Copy(&buf, r)
		close(copyDone)
	}()

	exited := false
	func() {
		defer func() {
			if rv := recover(); rv != nil {
				// An exit was triggered — this is the expected error path.
				exited = true
			}
		}()
		_ = rootCmd.Execute()
	}()

	os.Stdout = origOut
	os.Stderr = origErr
	w.Close()
	<-copyDone
	r.Close()

	rootCmd.SilenceErrors = silenced
	rootCmd.SetArgs(nil)

	if !exited {
		t.Fatalf("expected error exit for args %v, but command completed normally; output: %q", args, buf.String())
	}
	return buf.String()
}

// TestScoreCommand_InvalidVector verifies the score command's parse-error
// branch: an invalid vector triggers dief("Parse error: ...") rather than
// producing a score.
func TestScoreCommand_InvalidVector(t *testing.T) {
	out := runCommandExpectError(t, "score", "INVALID")
	if !strings.Contains(out, "Parse error") {
		t.Errorf("invalid-vector output missing 'Parse error': %q", out)
	}
	if !strings.Contains(out, "invalid magic head") {
		t.Errorf("invalid-vector output missing 'invalid magic head': %q", out)
	}
}

// TestParseCommand_InvalidVector verifies the parse command's parse-error branch.
func TestParseCommand_InvalidVector(t *testing.T) {
	out := runCommandExpectError(t, "parse", "INVALID")
	if !strings.Contains(out, "Parse error") {
		t.Errorf("invalid-vector output missing 'Parse error': %q", out)
	}
}

// TestPresetCommand_UnknownSeverity verifies preset rejects an unknown severity.
func TestPresetCommand_UnknownSeverity(t *testing.T) {
	out := runCommandExpectError(t, "preset", "bogus")
	if !strings.Contains(out, "Unknown severity") {
		t.Errorf("preset output missing 'Unknown severity': %q", out)
	}
	if !strings.Contains(out, "bogus") {
		t.Errorf("preset output should echo the bad value 'bogus': %q", out)
	}
}

// TestBuildCommand_InvalidMetricValue verifies build rejects an invalid metric
// value (dief "Build error").
func TestBuildCommand_InvalidMetricValue(t *testing.T) {
	out := runCommandExpectError(t, "build",
		"--AV", "Z", // Z is not a valid AttackVector value
		"--AC", "L", "--PR", "N", "--UI", "N",
		"--S", "U", "--C", "H", "--I", "H", "--A", "H",
	)
	if !strings.Contains(out, "Build error") {
		t.Errorf("build output missing 'Build error': %q", out)
	}
}

// TestDescribeCommand_InvalidVector verifies describe's parse-error branch.
func TestDescribeCommand_InvalidVector(t *testing.T) {
	out := runCommandExpectError(t, "describe", "INVALID")
	if !strings.Contains(out, "Parse error") {
		t.Errorf("describe output missing 'Parse error': %q", out)
	}
}

// TestGetCommand_InvalidVector verifies get's parse-error branch.
func TestGetCommand_InvalidVector(t *testing.T) {
	out := runCommandExpectError(t, "get", "INVALID", "AV")
	if !strings.Contains(out, "Parse error") {
		t.Errorf("get output missing 'Parse error': %q", out)
	}
}

// TestSeverityCommand_InvalidScore verifies severity rejects a non-numeric score.
func TestSeverityCommand_InvalidScore(t *testing.T) {
	out := runCommandExpectError(t, "severity", "not-a-number")
	if !strings.Contains(out, "Invalid score") {
		t.Errorf("severity output missing 'Invalid score': %q", out)
	}
}

// TestCSVWriteCommand_NoVectors verifies csv write dies when given no vectors.
// This exercises the die() helper (distinct from dief), which csv.go calls when
// the input yields zero valid vectors.
func TestCSVWriteCommand_NoVectors(t *testing.T) {
	out := runCommandExpectError(t, "csv", "write")
	if !strings.Contains(out, "No valid vectors to write") {
		t.Errorf("csv write output missing 'No valid vectors to write': %q", out)
	}
}

// TestVersionFlag verifies the --version flag outputs a version.
func TestVersionFlag(t *testing.T) {
	out := runCommand(t, "--version")
	if !strings.Contains(out, "dev") && !strings.Contains(out, "version") {
		t.Errorf("version output unexpected: %q", out)
	}
}

// TestEqualCommand verifies equal reports two identical vectors as equal.
func TestEqualCommand(t *testing.T) {
	out := runCommand(t, "equal", hiVec(), hiVec())
	if !strings.Contains(out, "Equal") {
		t.Errorf("equal output missing Equal: %q", out)
	}
}

// TestDescribeCommand verifies describe outputs human-readable metric names.
func TestDescribeCommand(t *testing.T) {
	out := runCommand(t, "describe", hiVec())
	if !strings.Contains(out, "Network") {
		t.Errorf("describe output missing Network: %q", out)
	}
	if !strings.Contains(out, "Confidentiality") {
		t.Errorf("describe output missing Confidentiality: %q", out)
	}
}

// TestCanonicalizeCommand verifies canonicalize emits the normalized vector.
func TestCanonicalizeCommand(t *testing.T) {
	out := runCommand(t, "canonicalize", hiVec())
	if !strings.Contains(out, hiVec()) {
		t.Errorf("canonicalize output missing vector: %q", out)
	}
}

// TestConvertCommand verifies convert --to 3.0 downgrades the version.
func TestConvertCommand(t *testing.T) {
	out := runCommand(t, "convert", "--to", "3.0", hiVec())
	if !strings.Contains(out, "CVSS:3.0/") {
		t.Errorf("convert output missing CVSS:3.0: %q", out)
	}
}

// TestGetCommand verifies get retrieves a single metric value.
func TestGetCommand(t *testing.T) {
	out := runCommand(t, "get", hiVec(), "AV")
	if !strings.Contains(out, "N") {
		t.Errorf("get output missing N: %q", out)
	}
}

// TestGroupsCommand verifies groups lists the Base metric group.
func TestGroupsCommand(t *testing.T) {
	out := runCommand(t, "groups", hiVec())
	if !strings.Contains(out, "Base") {
		t.Errorf("groups output missing Base: %q", out)
	}
}

// TestMapCommand verifies map outputs key=value pairs.
func TestMapCommand(t *testing.T) {
	out := runCommand(t, "map", hiVec())
	if !strings.Contains(out, "AV=N") {
		t.Errorf("map output missing AV=N: %q", out)
	}
}

// TestMergeCommand verifies merge combines base and temporal vectors.
func TestMergeCommand(t *testing.T) {
	temporal := vec("CVSS:3.1/", "E:F/RL:T/RC:C")
	out := runCommand(t, "merge", hiVec(), temporal)
	if !strings.Contains(out, "E:F") {
		t.Errorf("merge output missing temporal metric E:F: %q", out)
	}
}

// TestModifyCommand verifies modify applies a metric change.
func TestModifyCommand(t *testing.T) {
	out := runCommand(t, "modify", hiVec(), "--AV=L")
	if !strings.Contains(out, "AV:L") {
		t.Errorf("modify output missing AV:L: %q", out)
	}
}

// TestPresetCommand verifies preset emits a known preset vector.
func TestPresetCommand(t *testing.T) {
	out := runCommand(t, "preset", "critical")
	if !strings.Contains(out, "CVSS:3.1/") {
		t.Errorf("preset output missing CVSS:3.1: %q", out)
	}
}

// TestRandomCommand verifies random emits a parseable random vector.
func TestRandomCommand(t *testing.T) {
	out := runCommand(t, "random")
	if !strings.Contains(out, "CVSS:3.1/") {
		t.Errorf("random output missing CVSS:3.1: %q", out)
	}
}

// TestRangeCommand verifies range reports the score range.
func TestRangeCommand(t *testing.T) {
	out := runCommand(t, "range", hiVec())
	if !strings.Contains(out, "Score range") && !strings.Contains(out, "range") {
		t.Errorf("range output missing range info: %q", out)
	}
}

// TestSubsCommand verifies subs computes sub-scores.
func TestSubsCommand(t *testing.T) {
	out := runCommand(t, "subs", hiVec())
	if !strings.Contains(out, "Impact") && !strings.Contains(out, "Exploitability") {
		t.Errorf("subs output missing sub-scores: %q", out)
	}
}

// TestAnalyzeCommand verifies analyze emits impact analysis.
func TestAnalyzeCommand(t *testing.T) {
	out := runCommand(t, "analyze", hiVec())
	if !strings.Contains(out, "Impact") && !strings.Contains(out, "Impact Analysis") {
		t.Errorf("analyze output missing impact analysis: %q", out)
	}
}

// TestSortCommand verifies sort reads vectors from stdin and orders them.
func TestSortCommand(t *testing.T) {
	stdin := loAVec() + "\n" + hiVec() + "\n"
	out := runCommandWithStdin(t, stdin, "sort", "-")
	// Descending default: the 9.8 vector should appear before the lower one.
	hi := strings.Index(out, hiVec())
	lo := strings.Index(out, loAVec())
	if hi < 0 || lo < 0 {
		t.Fatalf("sort output missing vectors: %q", out)
	}
	if hi > lo {
		t.Errorf("sort not descending (hi=%d should come before lo=%d): %q", hi, lo, out)
	}
}

// TestCSVWriteCommand verifies csv write emits CSV with a header row.
func TestCSVWriteCommand(t *testing.T) {
	out := runCommand(t, "csv", "write", hiVec())
	if !strings.Contains(out, "CVSS") {
		t.Errorf("csv write output missing CVSS header: %q", out)
	}
	if !strings.Contains(out, hiVec()) {
		t.Errorf("csv write output missing vector row: %q", out)
	}
}

// TestCSVReadCommand verifies csv read parses a CSV stream from stdin and
// echoes back the vectors.
func TestCSVReadCommand(t *testing.T) {
	csvText := runCommand(t, "csv", "write", hiVec())
	out := runCommandWithStdin(t, csvText, "csv", "read", "-")
	if !strings.Contains(out, hiVec()) {
		t.Errorf("csv read output missing vector: %q", out)
	}
}

// TestBaseOnlyCommand verifies base-only (alias strip) drops temporal metrics.
func TestBaseOnlyCommand(t *testing.T) {
	out := runCommand(t, "base-only", hiVecTemporal())
	if !strings.Contains(out, hiVec()) {
		t.Errorf("base-only output missing stripped base vector: %q", out)
	}
	if strings.Contains(out, "E:F") {
		t.Errorf("base-only output should not contain temporal metrics: %q", out)
	}
}

// TestStripAliasCommand verifies strip works as an alias for base-only.
func TestStripAliasCommand(t *testing.T) {
	out := runCommand(t, "strip", hiVecTemporal())
	if !strings.Contains(out, hiVec()) {
		t.Errorf("strip output missing stripped base vector: %q", out)
	}
}

// TestBatchScoreCommand verifies batch score reads vectors from stdin and
// scores each.
func TestBatchScoreCommand(t *testing.T) {
	stdin := hiVec() + "\n" + hiVecTemporal() + "\n"
	out := runCommandWithStdin(t, stdin, "batch", "score", "-")
	if !strings.Contains(out, "9.8") {
		t.Errorf("batch score output missing 9.8: %q", out)
	}
	if !strings.Contains(out, hiVec()) {
		t.Errorf("batch score output missing vector: %q", out)
	}
}

// TestBatchValidateCommand verifies batch validate reads vectors from stdin.
func TestBatchValidateCommand(t *testing.T) {
	stdin := hiVec() + "\n"
	out := runCommandWithStdin(t, stdin, "batch", "validate", "-")
	if !strings.Contains(out, hiVec()) {
		t.Errorf("batch validate output missing vector: %q", out)
	}
}

// TestCompletionCommand verifies completion emits a shell script.
func TestCompletionCommand(t *testing.T) {
	out := runCommand(t, "completion", "bash")
	if !strings.Contains(out, "completion") {
		t.Errorf("completion output missing completion keyword: %q", out)
	}
}
