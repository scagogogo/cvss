---
title: Map & Vector-Value Construction
description: cvss.FromMap / MustFromMap / ToMap / FromVectorValues — build a Cvss3x from a map[string]string or key:value pairs (note the "version" key), and serialize back to a map.
---

# 🗂️ Map & Vector-Value Construction

🗂️ Feature · `pkg/cvss`

`FromMap` and `FromVectorValues` construct a `*Cvss3x` from loosely-typed input — a `map[string]string` or a variadic list of `"AV:N"` pairs — while `ToMap` is the inverse. They are the glue for configs, CSV rows, and CLI flags where you don't want to assemble a full vector string.

## Synopsis

```go
cv, err := cvss.FromMap(map[string]string{
    "version": "3.1",
    "AV": "N", "AC": "L", "PR": "N", "UI": "N",
    "S": "U", "C": "H", "I": "H", "A": "H",
    "E": "F", "RL": "T",
})
// or: cvss.FromVectorValues("3.1", "AV:N", "AC:L", ...)
m := cv.ToMap() // round-trip back to a map
```

## How It Works

`FromMap` parses the `version` key into `Major/MinorVersion`, then iterates the remaining entries dispatching each via `mapKeyValueToStruct` (which calls `vector.GetVectorByShortName`); per-key errors are accumulated and returned together. `FromVectorValues` splits each `"KEY:VALUE"` pair at the colon. `ToMap` walks all three sub-structs and emits only the non-nil metrics plus `version`.

```mermaid
flowchart TD
    Map[🟦 map string string + version key] --> FromMap
    Pairs["🟦 \"AV:N\",\"AC:L\",... variadic"] --> FromVV["FromVectorValues(version, pairs...)"]

    FromMap --> ParseVer[🔢 parseVersionString]
    ParseVer -- error --> VErr("[🔴 invalid version]")
    ParseVer -- ok --> Init[🟣 init *Cvss3x 3.x]

    FromVV --> Split["✂️ splitKeyValue at ':'"]
    Split -- error --> SErr("[🔴 missing colon]")
    Split -- ok --> Init

    Init --> Loop["🔄 each key:value"]
    Loop --> MapKV[🗺️ mapKeyValueToStruct]
    MapKV --> Fac[🔍 vector.GetVectorByShortName]
    Fac -- error --> Acc[📋 accumulate error]
    Fac -- ok --> Set[✏️ set field, lazy-allocate sub-struct]
    Set --> Loop
    Acc --> Loop
    Loop --> Done{"🟡 any errors?"}
    Done -- yes --> FErr("[🔴 FromMap errors]")
    Done -- no --> FOk("[✅ *Cvss3x]")

    FOk --> ToMap["ToMap (inverse)"]
    ToMap --> Walk["🔄 walk Base/Temporal/Environmental"]
    Walk --> Emit[🟢 emit non-nil metrics + version]
    Emit --> MOut("[✅ map string string]")
```

## API Reference

### FromMap

```go
func FromMap(m map[string]string) (*Cvss3x, error)
```

Builds a `*Cvss3x` from short-name/short-value pairs. A `"version"` key (value `"3.0"` or `"3.1"`) sets the version; if absent, the result defaults to v3.1. Every other key must be a recognized metric short name with a valid short value; `FromMap` collects **all** errors and returns them as a single wrapped error (`FromMap errors: [...]`). A `nil` map returns `map is nil`.

```go
cv, err := cvss.FromMap(map[string]string{"version": "3.1", "AV": "N", "AC": "L"})
```

::: tip The "version" key is special
It is the only non-metric key. Everything else is dispatched to the matching `vector.Get*` factory, so an unknown key like `"XX"` or an invalid value like `"AV": "Q"` becomes an entry in the error list.
:::

### MustFromMap

```go
func MustFromMap(m map[string]string) *Cvss3x
```

Wraps `FromMap` and panics on error. Use it for compile-time-known maps where a bad entry is a programmer bug.

```go
cv := cvss.MustFromMap(map[string]string{"version": "3.1", "AV": "N", /* ... */})
```

### ToMap

```go
func (x *Cvss3x) ToMap() map[string]string
```

Inverse of `FromMap`. Returns a map with a `"version"` key and one entry per **set** metric (short name -> short value). Unset metrics are omitted. Returns `nil` for a nil receiver. Note: `FromMap(ToMap(x))` round-trips losslessly because both sides only carry set metrics.

```go
m := cv.ToMap() // {"version":"3.1", "AV":"N", "AC":"L", ...}
```

### FromVectorValues

```go
func FromVectorValues(version string, pairs ...string) (*Cvss3x, error)
```

Takes the version as the first argument and `"KEY:VALUE"` pairs as varargs. Each pair must contain a colon; a missing colon yields `invalid pair "AVN": missing colon separator`. Unlike `FromMap`, this function returns on the **first** error (it does not aggregate). At least one pair is required.

```go
cv, err := cvss.FromVectorValues("3.1", "AV:N", "AC:L", "PR:N", "UI:N",
    "S:U", "C:H", "I:H", "A:H")
```

::: warning FromMap aggregates, FromVectorValues fails fast
`FromMap` collects every error and reports them together; `FromVectorValues` stops at the first bad pair. Pick the one that matches your input's failure mode — config files usually want aggregation, flag parsing usually wants fail-fast.
:::

## Example

```go
package main

import (
    "fmt"

    "github.com/scagogogo/cvss-skills/pkg/cvss"
)

func main() {
    // Build from a map (e.g. a parsed config row).
    cv, err := cvss.FromMap(map[string]string{
        "version": "3.1",
        "AV": "N", "AC": "L", "PR": "N", "UI": "N",
        "S": "U", "C": "H", "I": "H", "A": "H",
        "E": "F", "RL": "T", "RC": "C",
    })
    if err != nil {
        panic(err)
    }
    fmt.Println(cv.String())

    // Round-trip back to a map; only set metrics appear.
    m := cv.ToMap()
    fmt.Println(m["AV"], m["E"]) // N F
    fmt.Println(m["version"])     // 3.1

    // FromVectorValues: version first, then "KEY:VALUE" pairs.
    cv2, err := cvss.FromVectorValues("3.1",
        "AV:N", "AC:L", "PR:N", "UI:N",
        "S:U", "C:H", "I:H", "A:H")
    if err != nil {
        panic(err)
    }
    fmt.Println(cv2.HasTemporalMetrics()) // false — no E/RL/RC

    // MustFromMap panics on a bad value — appropriate for literals.
    func() {
        defer func() { recover() }()
        cvss.MustFromMap(map[string]string{"version": "3.1", "AV": "Q"})
    }()

    // FromMap aggregates all errors into one message.
    _, err = cvss.FromMap(map[string]string{
        "version": "3.1", "AV": "Q", "AC": "Z",
    })
    fmt.Println(err) // FromMap errors: [AV=Q: ... AC=Z: ...]
}
```

## Related

- [Accessor](/sdk/accessor) — `GetMetricValue` / `SetMetricValue` for single-metric reads/writes
- [Builder Pattern](/sdk/builder) — typed, fluent construction alternative
- [pkg/vector](/sdk/vector) — the `Get*` factories that validate each value
- CLI: [`map`](/cli/commands/map)
