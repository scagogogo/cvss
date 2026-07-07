---
title: Sentinel Errors
description: The four sentinel errors exported from pkg/cvss/errors.go — ErrNilReceiver, ErrIncompleteBaseMetrics, ErrUnsupportedVersion, ErrInvalidMetricValue — for errors.Is matching across the SDK.
---

# 🚨 Sentinel Errors

`pkg/cvss/errors.go` · 4 exported sentinel errors

> Structured validation errors (`ValidationError` / `ValidationErrors`) live in `pkg/cvss/validate.go` and are documented at [/sdk/validation](/sdk/validation). This page covers only the four sentinel errors declared in `errors.go`.

## Synopsis

`errors.go` declares four package-level sentinel error variables so callers can match them with `errors.Is` instead of string comparison. `ErrNilReceiver` is returned throughout the SDK (the `With*` method-chain helpers in `pkg/cvss/with_method.go`, plus `batch.go`, `score_range.go`, `accessor.go`, `conversion.go` and `impact.go`). The other three — `ErrIncompleteBaseMetrics`, `ErrUnsupportedVersion`, `ErrInvalidMetricValue` — are exported as stable sentinels for callers to use/compare against; note that the SDK's own `Check()` and `Calculator` currently report equivalent conditions via `fmt.Errorf` strings rather than wrapping these sentinels, so `errors.Is` on those code paths will not match them. They are intended for application-level error classification and for any code that wants to wrap/return a canonical CVSS error.

```go
var cv *cvss.Cvss3x // nil
_, err := cv.WithAVMethod('N')
if errors.Is(err, cvss.ErrNilReceiver) {
    // handle nil-receiver case
}
```

## How It Works

The four sentinels are stable values for `errors.Is` matching. `ErrNilReceiver` is returned directly by the nil-guarded methods across the SDK; the other three are exported as canonical classifiers — application code can wrap/return them, while the SDK's own `Check()`/`Calculator` paths report equivalent conditions via `fmt.Errorf` strings that do **not** wrap these sentinels.

```mermaid
flowchart TD
    Call[📞 method call] --> Nil{"🟡 receiver nil?"}
    Nil -- yes --> ENR[🔴 ErrNilReceiver]
    Nil -- no --> Src{"🟡 input kind?"}

    Src -- nil receiver only<br/>With*/accessor/batch/score_range --> ENR

    Src -- version not 3.0/3.1 --> EUV["🔴 ErrUnsupportedVersion<br/>canonical classifier"]
    Src -- base metric missing --> EIBM["🔴 ErrIncompleteBaseMetrics<br/>canonical classifier"]
    Src -- invalid metric value --> EIMV["🔴 ErrInvalidMetricValue<br/>canonical classifier"]

    note1["ℹ️ Check()/Calculator report these<br/>conditions via fmt.Errorf strings,<br/>NOT wrapping the sentinels"] -.-> Src

    ENR --> Match["errors.Is(err, sentinel)"]
    EUV --> Match
    EIBM --> Match
    EIMV --> Match
    Match --> Handle("[\"✅ classify & handle\"]")
```

## API Reference

```go
var (
    ErrNilReceiver          = errors.New("nil receiver")
    ErrIncompleteBaseMetrics = errors.New("incomplete base metrics")
    ErrUnsupportedVersion   = errors.New("unsupported CVSS version")
    ErrInvalidMetricValue   = errors.New("invalid metric value")
)
```

| Sentinel | `Error()` text | Intended meaning |
| --- | --- | --- |
| `ErrNilReceiver` | `nil receiver` | A method was invoked on a `nil` `*Cvss3x` (or nil sub-receiver). **Returned by** the `With*` method-chain helpers, batch helpers, `GetScoreRange`, accessors, conversion and impact helpers when their receiver is nil. |
| `ErrIncompleteBaseMetrics` | `incomplete base metrics` | The base metrics are not fully populated. Exported as a canonical sentinel; the SDK's own `Check()` reports the same condition via `fmt.Errorf` strings, so match by sentinel only if your code returns/wraps this value. |
| `ErrUnsupportedVersion` | `unsupported CVSS version` | The CVSS version is not one the SDK supports (only 3.0 and 3.1). Exported as a canonical sentinel; `Cvss3x.Check()` reports the same condition via `fmt.Errorf`. |
| `ErrInvalidMetricValue` | `invalid metric value` | A metric carries a value that is not legal for its category. Exported as a canonical sentinel for application-level classification. |

All four are plain `errors.New` values — wrap-free and safe to compare with `errors.Is`.

## Example

```go
package main

import (
	"errors"
	"fmt"

	"github.com/scagogogo/cvss-skills/pkg/cvss"
)

func main() {
	var cv *cvss.Cvss3x // nil

	_, err := cv.WithAVMethod('N')
	switch {
	case errors.Is(err, cvss.ErrNilReceiver):
		fmt.Println("receiver was nil, skip")
	case errors.Is(err, cvss.ErrIncompleteBaseMetrics):
		fmt.Println("base metrics incomplete")
	case errors.Is(err, cvss.ErrUnsupportedVersion):
		fmt.Println("unsupported version")
	case errors.Is(err, cvss.ErrInvalidMetricValue):
		fmt.Println("invalid metric value")
	default:
		fmt.Println("other error:", err)
	}
}
```

## Related

- [/sdk/validation](/sdk/validation) — `ValidationError` / `ValidationErrors` and the `Check` / `Validate` entry points
- [/sdk/cvss](/sdk/cvss) — the `Cvss3x` type whose methods return these sentinels
- [/sdk/calculator](/sdk/calculator) — scoring helpers that surface `ErrNilReceiver` / `ErrIncompleteBaseMetrics`
