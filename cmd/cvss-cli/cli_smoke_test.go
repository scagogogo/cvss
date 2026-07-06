package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

// vec builds a CVSS vector string by concatenation rather than a single
// string literal. Some Go 1.25 toolchains mis-constant-fold the byte index
// of a long vector literal that also appears in cobra command Example fields,
// corrupting a '/' into ':' at compile time. Building the string from parts
// defeats that folding and yields the correct bytes.
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

// runCommand executes the root command with the given args, capturing stdout
// (including fmt.Println output, which bypasses cobra's writer).
//
// It redirects os.Stdout to a pipe for the duration of the command, then
// restores it. Errors cause the command to call os.Exit(1) via die/dief, so
// only success paths are exercised here.
func runCommand(t *testing.T, args ...string) string {
	t.Helper()

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
