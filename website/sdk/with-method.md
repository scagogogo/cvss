---
title: With-Method (Immutable Setters)
description: cvss.Cvss3x.WithAVMethod ... WithMAMethod / WithVersionMethod / WithTemporalMethod — chainable, immutable per-metric setters that return a modified copy and never mutate the receiver.
---

# 🛠️ With-Method (Immutable Setters)

🛠️ Feature · `pkg/cvss`

The `With*Method` family is the immutable counterpart to `SetMetricValue`: each call returns a **modified copy** of the receiver with one metric (or one group) changed, leaving the original untouched. Because every method takes and returns `*Cvss3x`, they chain naturally for a fluent, copy-on-write edit style.

## Synopsis

```go
step1, err := cv.WithAVMethod('L')  // AV:N -> AV:L on a copy
modified, err := step1.WithSMethod('C') // S:U -> S:C on that copy
```

Each `With<Metric>Method(val rune)` validates `val` against the matching `vector.Get*` factory and returns an error wrapped as `<shortName>: <cause>` on failure. Setting a Temporal or Environmental metric lazily allocates the corresponding sub-struct on the returned copy (mirroring `SetMetricValue`).

## How It Works

Every `With*Method` follows the same shape: nil check → factory lookup → `Clone` → write the field on the clone → return the clone. `WithTemporalMethod` chains `WithE/RL/RC`; group setters on Environmental allocate the sub-struct first. The receiver is never written to, so chains compose safely.

```mermaid
flowchart TD
    CV[📦 *Cvss3x receiver] --> Nil{"🟡 nil?"}
    Nil -- yes --> NErr("[🔴 ErrNilReceiver]")
    Nil -- no --> Fac[🔍 vector.Get* value]
    Fac -- error --> FErr("[\"🔴 wrapped \\"NAME: cause\\"\"]")
    Fac -- ok --> Clone[🟢 Clone receiver]
    Clone --> Group{"🟡 Temporal/Env field?"}
    Group -- yes --> Alloc[🟣 lazy-allocate sub-struct]
    Group -- no --> Write
    Alloc --> Write[✏️ set field on clone]
    Write --> Out("[✅ modified *Cvss3x\nreceiver unchanged]")

    Out --> Chain["🔗 .WithSMethod('C') repeats"]
    Chain --> CV2[📦 previous copy]

    CV -.compare.-> Set["SetMetricValue: same clone-and-write\nbut resolves by shortName string"]
```

## API Reference

### Base metric setters

```go
func (x *Cvss3x) WithAVMethod(val rune) (*Cvss3x, error)  // Attack Vector
func (x *Cvss3x) WithACMethod(val rune) (*Cvss3x, error)  // Attack Complexity
func (x *Cvss3x) WithPRMethod(val rune) (*Cvss3x, error)  // Privileges Required
func (x *Cvss3x) WithUIMethod(val rune) (*Cvss3x, error)  // User Interaction
func (x *Cvss3x) WithSMethod(val rune) (*Cvss3x, error)   // Scope
func (x *Cvss3x) WithCMethod(val rune) (*Cvss3x, error)   // Confidentiality
func (x *Cvss3x) WithIMethod(val rune) (*Cvss3x, error)   // Integrity
func (x *Cvss3x) WithAMethod(val rune) (*Cvss3x, error)   // Availability
```

Each clones the receiver (`x.Clone()`), sets the field on the copy, and returns it. A nil receiver returns `(nil, ErrNilReceiver)`.

### Temporal metric setters

```go
func (x *Cvss3x) WithEMethod(val rune) (*Cvss3x, error)   // Exploit Code Maturity
func (x *Cvss3x) WithRLMethod(val rune) (*Cvss3x, error)  // Remediation Level
func (x *Cvss3x) WithRCMethod(val rune) (*Cvss3x, error)  // Report Confidence

func (x *Cvss3x) WithTemporalMethod(e, rl, rc rune) (*Cvss3x, error)
```

The singletons lazily allocate `Cvss3xTemporal` on the copy when it is nil. `WithTemporalMethod` sets all three temporal metrics in one call, chaining `WithEMethod` -> `WithRLMethod` -> `WithRCMethod` and short-circuiting on the first error.

### Environmental metric setters

```go
func (x *Cvss3x) WithCRMethod(val rune) (*Cvss3x, error)  // Confidentiality Requirement
func (x *Cvss3x) WithIRMethod(val rune) (*Cvss3x, error)  // Integrity Requirement
func (x *Cvss3x) WithARMethod(val rune) (*Cvss3x, error)  // Availability Requirement
func (x *Cvss3x) WithMAVMethod(val rune) (*Cvss3x, error) // Modified Attack Vector
func (x *Cvss3x) WithMACMethod(val rune) (*Cvss3x, error) // Modified Attack Complexity
func (x *Cvss3x) WithMPRMethod(val rune) (*Cvss3x, error) // Modified Privileges Required
func (x *Cvss3x) WithMUIMethod(val rune) (*Cvss3x, error) // Modified User Interaction
func (x *Cvss3x) WithMSMethod(val rune) (*Cvss3x, error)  // Modified Scope
func (x *Cvss3x) WithMCMethod(val rune) (*Cvss3x, error)  // Modified Confidentiality
func (x *Cvss3x) WithMIMethod(val rune) (*Cvss3x, error)  // Modified Integrity
func (x *Cvss3x) WithMAMethod(val rune) (*Cvss3x, error)  // Modified Availability
```

Each lazily allocates `Cvss3xEnvironmental` on the copy when it is nil.

### Version setter

```go
func (x *Cvss3x) WithVersionMethod(major, minor int) (*Cvss3x, error)
```

Returns a copy with the version number changed. Unlike `ConvertToVersion`, it does **not** validate that the version is 3.0 or 3.1 — it just sets the fields. Prefer `ConvertToVersion` when you want validation.

::: tip With*Method vs SetMetricValue vs ConvertToVersion
`SetMetricValue("AV", 'L')` and `WithAVMethod('L')` do the same job; the former is generic (metric name as a string), the latter is typed and chainable. `WithVersionMethod` is the raw version setter; `ConvertToVersion` adds version validation and is the safe default.
:::

::: warning Errors break the chain
Because each method returns `(*Cvss3x, error)`, you cannot chain past an error without reassigning. The idiomatic pattern is to check the error at the end of the chain (or use `Must*`-style helpers) — a mid-chain error leaves you with the partial result from the last successful step only if you reassign at each step.
:::

## Example

```go
package main

import (
    "fmt"

    "github.com/scagogogo/cvss-skills/pkg/parser"
)

func main() {
    cv, err := parser.ParseString("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    if err != nil {
        panic(err)
    }

    // Chain immutable edits; the original is untouched.
    step1, err := cv.WithAVMethod('L') // AV:N -> AV:L on a copy
    if err != nil {
        panic(err)
    }
    harder, err := step1.WithSMethod('C') // S:U -> S:C on that copy
    if err != nil {
        panic(err)
    }
    fmt.Println(cv.String())      // still .../AV:N/.../S:U/...
    fmt.Println(harder.String())  // .../AV:L/.../S:C/...

    // Add the full temporal group in one call.
    withTemp, err := cv.WithTemporalMethod('F', 'U', 'C')
    if err != nil {
        panic(err)
    }
    fmt.Println(withTemp.HasTemporalMetrics()) // true

    // Add a modified environmental metric; the group is lazily allocated.
    withEnv, err := cv.WithMAMethod('L')
    if err != nil {
        panic(err)
    }
    fmt.Println(withEnv.HasEnvironmentalMetrics()) // true

    // An invalid value surfaces as a wrapped error.
    _, err = cv.WithAVMethod('Q')
    fmt.Println(err) // AV: unknown attack vector value: Q

    // Raw version change (no validation) vs ConvertToVersion (validated).
    raw, _ := cv.WithVersionMethod(3, 0)
    fmt.Println(raw.Version()) // 3.0
}
```

## Related

- [Accessor](/sdk/accessor) — the string-keyed `GetMetricValue` / `SetMetricValue` this mirrors
- [Conversion](/sdk/conversion) — `ConvertToVersion` vs the raw `WithVersionMethod`
- [Convenience](/sdk/convenience) — `Clone`, which every `With*Method` call relies on
- [Builder Pattern](/sdk/builder) — the mutable, fluent construction counterpart
- CLI: [`modify`](/cli/commands/modify)
