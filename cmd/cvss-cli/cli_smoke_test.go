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

// TestVersionFlag verifies the --version flag outputs a version.
func TestVersionFlag(t *testing.T) {
	out := runCommand(t, "--version")
	if !strings.Contains(out, "dev") && !strings.Contains(out, "version") {
		t.Errorf("version output unexpected: %q", out)
	}
}
