# CVSS Parse Skill

Parse a CVSS v3.0/v3.1 vector string into structured data.

📖 Full documentation: https://scagogogo.github.io/cvss-skills/sdk/parser

## CLI Command

```bash
cvss parse [vector-string]
cvss parse --relaxed --default-version 3.1 [vector-string-without-prefix]
```

## Output

Returns version, completeness status, metric presence flags, and human-readable description.

## Examples

```bash
# Standard parsing
cvss parse "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

# Relaxed parsing (no CVSS: prefix required)
cvss parse --relaxed "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
```

## Go SDK Usage

```go
// Standard parsing
cv, err := parser.ParseString("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

// Relaxed parsing
cv, err := parser.ParseRelaxed("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "3.1")

// Parse and validate in one step
cv, err := parser.ParseAndValidate("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

// Panic on failure
cv := parser.MustParse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
```

## Metric Keys

| Key | Metric | Values |
|-----|---------|--------|
| AV | Attack Vector | N/A/L/P |
| AC | Attack Complexity | L/H |
| PR | Privileges Required | N/L/H |
| UI | User Interaction | N/R |
| S | Scope | U/C |
| C | Confidentiality | H/L/N |
| I | Integrity | H/L/N |
| A | Availability | H/L/N |
| E | Exploit Code Maturity | X/U/P/F/H |
| RL | Remediation Level | X/O/T/W/U |
| RC | Report Confidence | X/U/R/C |
| CR | Confidentiality Requirement | X/H/M/L |
| IR | Integrity Requirement | X/H/M/L |
| AR | Availability Requirement | X/H/M/L |
| MAV | Modified Attack Vector | X/N/A/L/P |
| MAC | Modified Attack Complexity | X/L/H |
| MPR | Modified Privileges Required | X/N/L/H |
| MUI | Modified User Interaction | X/N/R |
| MS | Modified Scope | X/U/C |
| MC | Modified Confidentiality | X/H/L/N |
| MI | Modified Integrity | X/H/L/N |
| MA | Modified Availability | X/H/L/N |