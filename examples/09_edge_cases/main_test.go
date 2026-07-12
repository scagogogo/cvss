package main

import (
	"testing"

	"github.com/scagogogo/cvss-skills/pkg/cvss"
	"github.com/scagogogo/cvss-skills/pkg/parser"
)

// TestSafeParseVector covers safeParseVector's three branches: empty input
// (local error), valid vector (parse success), and malformed vector (parser
// error propagated).
func TestSafeParseVector(t *testing.T) {
	// Empty input returns a local error, not a parser error.
	cv, err := safeParseVector("")
	if cv != nil || err == nil {
		t.Errorf("safeParseVector(\"\") want (nil, error), got (%v, %v)", cv, err)
	}
	if err != nil && err.Error() != "向量字符串为空" {
		t.Errorf("empty input error message want '向量字符串为空', got %q", err.Error())
	}

	// Valid vector parses successfully.
	valid := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	cv, err = safeParseVector(valid)
	if err != nil {
		t.Errorf("safeParseVector(valid) unexpected error: %v", err)
	}
	if cv == nil || cv.String() != valid {
		t.Errorf("safeParseVector(valid) want vector %q, got %v", valid, cv)
	}

	// Malformed vector (bad magic head) propagates the parser error.
	cv, err = safeParseVector("INVALID")
	if cv != nil || err == nil {
		t.Errorf("safeParseVector(\"INVALID\") want (nil, error), got (%v, %v)", cv, err)
	}
}

// TestSafeCalculateScore covers the nil-receiver guard, a calculate-error path
// (incomplete metrics — Availability missing), and a normal scoring path.
func TestSafeCalculateScore(t *testing.T) {
	// nil receiver returns 0.0, SeverityNone.
	score, sev := safeCalculateScore(nil)
	if score != 0.0 || sev != cvss.SeverityNone {
		t.Errorf("safeCalculateScore(nil) want (0.0, SeverityNone), got (%v, %v)", score, sev)
	}

	// A vector missing required metrics causes Calculate() to error,
	// returning 0.0, SeverityNone. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H"
	// parses fine but lacks A — Calculate reports "Availability can not empty".
	incomplete, err := parser.ParseString("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H")
	if err != nil {
		t.Fatalf("ParseString(incomplete) setup failed: %v", err)
	}
	score, sev = safeCalculateScore(incomplete)
	if score != 0.0 || sev != cvss.SeverityNone {
		t.Errorf("safeCalculateScore(incomplete) want (0.0, SeverityNone), got (%v, %v)", score, sev)
	}

	// Normal vector scores 9.8 Critical.
	valid := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	cv, err := parser.ParseString(valid)
	if err != nil {
		t.Fatalf("ParseString: %v", err)
	}
	score, sev = safeCalculateScore(cv)
	if score != 9.8 {
		t.Errorf("safeCalculateScore(valid) want score 9.8, got %v", score)
	}
	if sev != cvss.SeverityCritical {
		t.Errorf("safeCalculateScore(valid) want SeverityCritical, got %v", sev)
	}
}

// TestIsValidVectorString covers the four branches: empty string, short/non-CVSS
// prefix, parseable failure, and valid vector.
func TestIsValidVectorString(t *testing.T) {
	// Empty string.
	if isValidVectorString("") {
		t.Errorf("isValidVectorString(\"\") want false")
	}
	// Short string not starting with "CVSS:".
	if isValidVectorString("abc") {
		t.Errorf("isValidVectorString(\"abc\") want false")
	}
	// Prefix correct but content unparseable.
	if isValidVectorString("CVSS:invalid") {
		t.Errorf("isValidVectorString(\"CVSS:invalid\") want false")
	}
	// Fully valid vector.
	if !isValidVectorString("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") {
		t.Errorf("isValidVectorString(valid) want true")
	}
}

// TestIsValidCvss covers every branch: nil receiver, MajorVersion<=0,
// nil base, each of the 8 base metrics individually nil (exercising every
// short-circuited || operand), and a fully valid Cvss3x.
func TestIsValidCvss(t *testing.T) {
	// nil receiver.
	if isValidCvss(nil) {
		t.Errorf("isValidCvss(nil) want false")
	}

	// MajorVersion<=0 path. Parse a valid vector then zero the version.
	cv0, err := parser.ParseString("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	if err != nil {
		t.Fatalf("ParseString: %v", err)
	}
	cv0.MajorVersion = 0
	if isValidCvss(cv0) {
		t.Errorf("isValidCvss(MajorVersion=0) want false")
	}

	// Non-nil Cvss3x but nil base — construct via parsing then nil out the base.
	cv, err := parser.ParseString("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	if err != nil {
		t.Fatalf("ParseString: %v", err)
	}
	cv.Cvss3xBase = nil
	if isValidCvss(cv) {
		t.Errorf("isValidCvss(cv with nil base) want false")
	}

	// Each base metric individually nil: all || operands must be reached at
	// least once across the cases. The first metric nil'd reaches operand 1;
	// to reach operand N, the first N-1 must stay non-nil and operand N nil.
	// Parsing a full vector gives all 8 metrics non-nil, so we nil them one
	// at a time in order, which means operand i is first-true only on the
	// case that nil's metric i — exercising every operand.
	metrics := []struct {
		name string
		set  func(base *cvss.Cvss3xBase)
	}{
		{"AttackVector", func(b *cvss.Cvss3xBase) { b.AttackVector = nil }},
		{"AttackComplexity", func(b *cvss.Cvss3xBase) { b.AttackComplexity = nil }},
		{"PrivilegesRequired", func(b *cvss.Cvss3xBase) { b.PrivilegesRequired = nil }},
		{"UserInteraction", func(b *cvss.Cvss3xBase) { b.UserInteraction = nil }},
		{"Scope", func(b *cvss.Cvss3xBase) { b.Scope = nil }},
		{"Confidentiality", func(b *cvss.Cvss3xBase) { b.Confidentiality = nil }},
		{"Integrity", func(b *cvss.Cvss3xBase) { b.Integrity = nil }},
		{"Availability", func(b *cvss.Cvss3xBase) { b.Availability = nil }},
	}
	for i, m := range metrics {
		// Re-parse each iteration so prior nil's don't accumulate; nil only
		// metric m, leaving metrics [0..i-1] non-nil so operand i is the
		// first-true (short-circuit) one.
		base, err := parser.ParseString("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
		if err != nil {
			t.Fatalf("ParseString: %v", err)
		}
		m.set(base.Cvss3xBase)
		if isValidCvss(base) {
			t.Errorf("case %d isValidCvss(%s=nil) want false", i, m.name)
		}
	}

	// Valid fully-populated Cvss3x.
	cv2, err := parser.ParseString("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	if err != nil {
		t.Fatalf("ParseString: %v", err)
	}
	if !isValidCvss(cv2) {
		t.Errorf("isValidCvss(valid) want true")
	}
}
