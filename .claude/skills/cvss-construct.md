# CVSS Construct Skill

Build CVSS vectors from scratch using multiple construction patterns.

📖 Full documentation: https://scagogogo.github.io/cvss-skills/cli/commands/build

## CLI Command

```bash
# Build from individual flags
cvss build --AV=N --AC=L --PR=N --UI=N --S=U --C=H --I=H --A=H
cvss build --AV=N --AC=L --PR=N --UI=N --S=U --C=H --I=H --A=H --E=F --RL=T --RC=C
cvss build --version=3.0 --AV=N --AC=L --PR=N --UI=N --S=C --C=H --I=H --A=H

# Generate preset vectors
cvss preset critical
cvss preset --version 3.0 high
cvss preset --score medium

# Generate random vectors
cvss random
cvss random --temporal --score
cvss random --full --version 3.0
```

## Construction Patterns (Go SDK)

### 1. Functional Options (Recommended)

```go
cv, err := cvss.NewCvss3xWithOptions(
    cvss.WithVersion31(),
    cvss.WithAV('N'), cvss.WithAC('L'), cvss.WithPR('N'), cvss.WithUI('N'),
    cvss.WithS('U'), cvss.WithC('H'), cvss.WithI('H'), cvss.WithA('H'),
    cvss.WithTemporal('F', 'T', 'C'),
    cvss.WithRequirements('H', 'M', 'L'),
)

// Preset combos
cv, err := cvss.NewCvss3xWithOptions(cvss.WithVersion31(), cvss.WithCriticalBase())
```

### 2. Builder Pattern

```go
cv, err := cvss.NewBuilder().Version(3, 1).
    AV('N').AC('L').PR('N').UI('N').S('U').C('H').I('H').A('H').
    E('F').RL('T').RC('C').
    BuildChecked()  // validates completeness
```

### 3. From Map

```go
cv, err := cvss.FromMap(map[string]string{
    "version": "3.1",
    "AV": "N", "AC": "L", "PR": "N", "UI": "N",
    "S": "U", "C": "H", "I": "H", "A": "H",
})
```

### 4. From Vector Values

```go
cv, err := cvss.FromVectorValues("3.1", "AV:N", "AC:L", "PR:N", "UI:N", "S:U", "C:H", "I:H", "A:H")
```

### 5. Direct Struct

```go
cv := cvss.NewCvss3x()
cv.MajorVersion = 3
cv.MinorVersion = 1
cv.Cvss3xBase.AttackVector = vector.AttackVectorNetwork
cv.Cvss3xBase.AttackComplexity = vector.AttackComplexityLow
// ... etc
```

### 6. Presets

```go
cv := cvss.CriticalV31()  // AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
cv := cvss.HighV31()      // AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
cv := cvss.MediumV31()    // AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N
cv := cvss.LowV31()       // AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N
cv := cvss.NoneV31()      // AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N
// Also: CriticalV30(), HighV30(), MediumV30(), LowV30(), NoneV30()
```

### 7. Chainable Modification

```go
base := cvss.CriticalV31()
modified, _ := base.WithAVMethod('L')         // returns copy, original unchanged
modified, _ = modified.WithTemporalMethod('F', 'T', 'C')
```

## Available Functional Options

| Category | Options |
|----------|---------|
| Version | `WithVersion(major,minor)`, `WithVersion31()`, `WithVersion30()` |
| Base | `WithAV`, `WithAC`, `WithPR`, `WithUI`, `WithS`, `WithC`, `WithI`, `WithA` |
| Temporal | `WithE`, `WithRL`, `WithRC`, `WithTemporal(e,rl,rc)` |
| Environmental | `WithCR`, `WithIR`, `WithAR`, `WithRequirements(cr,ir,ar)` |
| Modified | `WithMAV`, `WithMAC`, `WithMPR`, `WithMUI`, `WithMS`, `WithMC`, `WithMI`, `WithMA` |
| Presets | `WithCriticalBase()`, `WithHighBase()`, `WithMediumBase()`, `WithLowBase()`, `WithNoneBase()` |