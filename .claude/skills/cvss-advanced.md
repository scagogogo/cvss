# CVSS Advanced Skills

Advanced CVSS v3.x operations: impact analysis, sensitivity, batch processing, enumeration, version conversion.

📖 Full documentation: https://scagogogo.github.io/cvss-skills/tutorials/

## CLI Commands

```bash
# Impact + sensitivity analysis
cvss analyze "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

# Find metric changes to reach target score
cvss analyze --target 7.0 "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

# List all metric definitions
cvss enumerate

# Show specific metric details
cvss enumerate --metric AV

# Validate a metric:value pair
cvss enumerate --validate-value AV:N
```

## Go SDK: Impact Analysis

```go
cv := cvss.CriticalV31()

// Impact analysis: how each metric change affects the score
impacts, err := cvss.ImpactAnalysis(cv)
for _, mi := range impacts {
    fmt.Print(mi.String())
}

// Sensitivity analysis: which metrics have the largest score swing
sens, err := cvss.SensitivityAnalysis(cv)
for _, s := range sens {
    fmt.Println(s.String())  // "AV: 6.8 ~ 9.8 (swing: 3.0, current: 9.8)"
}

// Find minimum changes to reach a target score
changes, err := cvss.FindMetricChangesToReachTarget(cv, 7.0)
for _, c := range changes {
    fmt.Println(c.String())  // "AV: N → P (Δ-3.0, result: 6.8 Medium)"
}
```

## Go SDK: Batch Processing

```go
// Batch parse (parallel)
results := parser.BatchParse([]string{v1, v2, v3}, 4)
for _, r := range results {
    if r.Error != nil { continue }
    fmt.Println(r.Vector.String())
}

// Batch validate
results := parser.BatchValidate([]string{v1, v2, v3}, 4)

// Batch score
scoreResults := cvss.BatchScore([]*cvss.Cvss3x{cv1, cv2, cv3}, 4)
for _, r := range scoreResults {
    fmt.Printf("%.1f (%s)\n", r.Score, r.Severity)
}

// Batch all scores
allResults := cvss.BatchAllScores([]*cvss.Cvss3x{cv1, cv2, cv3}, 4)
```

## Go SDK: Enumeration

```go
// List all metrics with valid values
metrics := cvss.ListAllMetrics()  // []MetricInfo, 22+ metrics

// Get info for one metric
info, _ := cvss.GetMetricInfo("AV")
shortVals, longVals, _ := cvss.GetValidValues("AV")

// Check if a metric value is valid
cvss.IsValidMetricValue("AV", 'N')  // true
cvss.IsValidMetricValue("AV", 'Z')  // false

// Iterate all possible base vector combinations (2592 total)
iter := cvss.NewVectorIterator(1)  // 1 = v3.1, 0 = v3.0
for {
    cv := iter.Next()
    if cv == nil { break }
    fmt.Println(cv.String())
}
iter.Reset()  // start over
total := iter.TotalCombinations()  // 2592
```

## Go SDK: Score Range (Partial Vectors)

```go
// Calculate min/max scores for partial vectors
partial, _ := parser.ParseString("CVSS:3.1/AV:N/AC:L")
rng := cvss.GetScoreRange(partial)
fmt.Printf("%.1f ~ %.1f [%d metrics missing]\n",
    rng.MinScore, rng.MaxScore, rng.MissingCount)

// Get worst-case (highest score) vector
worst, score, _ := cvss.GetWorstCase(partial)

// Get best-case (lowest score) vector
best, score, _ := cvss.GetBestCase(partial)
```

## Go SDK: Version Conversion

```go
cv := cvss.CriticalV31()

// Convert version
v30, _ := cv.ConvertToVersion(3, 0)
v31, _ := v30.ConvertToVersion(3, 1)

// Convenience methods
v30, _ = cv.DowngradeTo30()
v31, _ = v30.UpgradeTo31()
```

## Go SDK: Generic Accessor

```go
cv := cvss.CriticalV31()

// Get metric value by name
shortVal, longVal, _ := cv.GetMetricValue("AV")  // 'N', "Network"

// Set metric value by name (returns copy)
modified, _ := cv.SetMetricValue("AV", 'L')  // AV changes to Local
modified, _ = cv.SetMetricValue("E", 'F')    // auto-creates temporal group

// Get metric groups
groups := cv.GetMetricGroups()  // []MetricGroup
for _, g := range groups {
    fmt.Println(g.Name, len(g.Metrics))
}

// Get vector strings by group
cv.GetBaseVectorString()          // CVSS:3.1/AV:N/...
cv.GetTemporalVectorString()      // + /E:F/RL:T/RC:C
cv.GetEnvironmentalVectorString() // full vector
```

## Go SDK: SQL / Sort / CSV / Canonicalize

```go
// database/sql Scanner/Valuer
var cv cvss.Cvss3x
rows.Scan(&cv)
result, _ := db.Exec("INSERT INTO vulns (cvss) VALUES (?)", cv)

// Sort by score
slice := cvss.NewCvss3xSlice(v1, v2, v3)
slice.Sort()            // descending (default)
slice.Asc().Sort()      // ascending
items := slice.Items()

// CSV I/O
cvss.WriteCSV(&buf, []*cvss.Cvss3x{v1, v2, v3})
vectors, _ := cvss.ReadCSV(&buf)
vectors, errors, _ := cvss.ReadCSVLax(&buf)  // tolerant mode

// Canonicalize
canonical, _ := cvss.Canonicalize("CVSS:3.1/S:U/C:H/I:H/A:H/AV:N/AC:L/PR:N/UI:N")
cvss.IsCanonical("CVSS:3.1/S:U/C:H/...")  // false
```
