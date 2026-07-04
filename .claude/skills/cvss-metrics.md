# CVSS Metrics Reference Skill

Complete reference for all CVSS v3.x metrics, values, and scores.

📖 Full documentation: https://scagogogo.github.io/cvss-skills/metrics/

## Base Metrics (Required, 8 total)

| Key | Name | Values & Scores |
|-----|------|-----------------|
| AV | Attack Vector | N=0.85, A=0.62, L=0.55, P=0.20 |
| AC | Attack Complexity | L=0.77, H=0.44 |
| PR | Privileges Required | N=0.85, L=0.62/0.68†, H=0.27/0.50† |
| UI | User Interaction | N=0.85, R=0.62(v3.1)/0.56(v3.0) |
| S | Scope | U=Unchanged, C=Changed |
| C | Confidentiality | H=0.56, L=0.22, N=0 |
| I | Integrity | H=0.56, L=0.22, N=0 |
| A | Availability | H=0.56, L=0.22, N=0 |

† PR scores depend on Scope: first value = Unchanged, second = Changed

## Temporal Metrics (Optional, 3 total)

| Key | Name | Values & Scores |
|-----|------|-----------------|
| E | Exploit Code Maturity | X=1.0, U=0.91, P=0.94, F=0.97, H=1.0 |
| RL | Remediation Level | X=1.0, O=0.95, T=0.96, W=0.97, U=1.0 |
| RC | Report Confidence | X=1.0, U=0.92, R=0.96, C=1.0 |

## Environmental Metrics (Optional, 11 total)

### Security Requirements

| Key | Name | Values & Factors |
|-----|------|-----------------|
| CR | Confidentiality Requirement | X=1.0, H=1.5, M=1.0, L=0.5 |
| IR | Integrity Requirement | X=1.0, H=1.5, M=1.0, L=0.5 |
| AR | Availability Requirement | X=1.0, H=1.5, M=1.0, L=0.5 |

### Modified Base Metrics

| Key | Name | Values |
|-----|------|--------|
| MAV | Modified Attack Vector | X + same as AV |
| MAC | Modified Attack Complexity | X + same as AC |
| MPR | Modified Privileges Required | X + same as PR |
| MUI | Modified User Interaction | X + same as UI |
| MS | Modified Scope | X + same as S |
| MC | Modified Confidentiality | X + same as C |
| MI | Modified Integrity | X + same as I |
| MA | Modified Availability | X + same as A |

X = Not Defined (score=1.0, falls back to base metric value)

## Context-Sensitive Scoring

**PR depends on Scope:**
- PR:Low = 0.62 (Scope Unchanged) or 0.68 (Scope Changed)
- PR:High = 0.27 (Scope Unchanged) or 0.50 (Scope Changed)

**UI depends on Version:**
- UI:Required = 0.62 (v3.1) or 0.56 (v3.0)

Use helper functions for correct scores:
```go
prScore := vector.GetPrivilegesRequiredScore(prVector, scopeChanged)
uiScore := vector.GetUserInteractionScore(uiVector, minorVersion)
scopeChanged := vector.IsScopeChanged(scopeVector)
modScopeChanged := vector.IsModifiedScopeChanged(modScopeVector, baseScopeVector)
```

## Vector String Format

```
CVSS:<major>.<minor>/<base-metrics>[/<temporal-metrics>][/<environmental-metrics>]
```

Example: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:T/RC:C/CR:H/IR:M/AR:L`