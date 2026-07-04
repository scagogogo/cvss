# CVSS Validate Skill

Validate CVSS v3.x vector strings for correctness and completeness.

📖 Full documentation: https://scagogogo.github.io/cvss-skills/cli/commands/validate

## CLI Command

```bash
cvss validate "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
```

Returns "Valid ✓" if the vector is well-formed and all required base metrics are present.

## Go SDK Usage

```go
cv, _ := parser.ParseString("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

// Short-circuit validation (returns on first error)
err := cv.Check()

// Collect-all-errors validation
err := cv.Validate()
if ve, ok := err.(cvss.ValidationErrors); ok {
    for _, e := range ve {
        fmt.Printf("Metric %s: %s\n", e.Metric, e.Message)
    }
    missing := ve.MissingMetrics()
}

// Quick completeness check
complete := cv.IsComplete()

// List missing base metrics
missing := cv.MissingMetrics()
```

## Validation Rules

1. **Version**: Major must be 3, Minor must be 0 or 1
2. **Base metrics**: All 8 (AV, AC, PR, UI, S, C, I, A) are required
3. **Temporal metrics**: Optional; if set, must have valid short names
4. **Environmental metrics**: Optional; if set, must have valid short names
5. **Metric values**: Must be from the allowed value set for each metric

## Sentinel Errors

Use `errors.Is()` for programmatic checking:

```go
errors.Is(err, cvss.ErrNilReceiver)
errors.Is(err, cvss.ErrIncompleteBaseMetrics)
errors.Is(err, cvss.ErrUnsupportedVersion)
errors.Is(err, cvss.ErrInvalidMetricValue)
```