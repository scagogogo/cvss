# CVSS Score Skill

Calculate CVSS v3.x scores and severity ratings.

📖 Full documentation: https://scagogogo.github.io/cvss-skills/cli/commands/score

## CLI Commands

```bash
# Overall score
cvss score "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

# All scores with severities
cvss score --all "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

# Per-metric breakdown
cvss score --breakdown "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

# JSON output
cvss score --format json "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

# Severity lookup from numeric score
cvss severity 9.8
```

## Score Hierarchy

1. **Base Score** — from 8 base metrics (AV, AC, PR, UI, S, C, I, A)
2. **Temporal Score** — base × E × RL × RC (if temporal metrics present)
3. **Environmental Score** — modified metrics + requirement factors × temporal (if environmental metrics present)

The `Calculate()` method returns the highest applicable score.

## Severity Thresholds

| Rating | Score Range |
|--------|------------|
| None | 0.0 |
| Low | 0.1 – 3.9 |
| Medium | 4.0 – 6.9 |
| High | 7.0 – 8.9 |
| Critical | 9.0 – 10.0 |

## Go SDK Usage

```go
cv, _ := parser.ParseString("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
calc := cvss.NewCalculator(cv)

// Overall score
score, _ := calc.Calculate()

// Individual scores
baseScore, _ := calc.GetBaseScore()
temporalScore, _ := calc.GetTemporalScore()
envScore, _ := calc.GetEnvironmentalScore()

// Sub-scores
impact, _ := calc.GetImpactSubScore()
exploitability, _ := calc.GetExploitabilitySubScore()

// All at once
all, _ := calc.GetAllScores()

// Severity
severity := cvss.GetSeverity(score)  // or calc.GetSeverityRating(score)

// Per-metric breakdown
breakdown, _ := calc.GetScoreBreakdown()
```

## Score Formulas

**Base Score:**
- ISCBase = 1 - [(1-C) × (1-I) × (1-A)]
- Impact = 6.42 × ISCBase (Scope Unchanged) or 7.52×(ISCBase-0.029) - 3.25×(ISCBase×0.9731-0.02)^13 (Scope Changed)
- Exploitability = 8.22 × AV × AC × PR × UI
- BaseScore = Roundup(min(Impact + Exploitability, 10))

**Temporal Score:** Roundup(BaseScore × E × RL × RC)

**Environmental Score:** Uses modified metrics + CIA requirement factors, then × E × RL × RC