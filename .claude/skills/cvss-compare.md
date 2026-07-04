# CVSS Compare Skill

Compare two CVSS vectors: diff, merge, and distance calculations.

📖 Full documentation: https://scagogogo.github.io/cvss-skills/cli/commands/diff

## CLI Commands

```bash
# Show differences between two vectors
cvss diff "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

# Calculate distance metrics
cvss distance "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

# Distance with environmental metrics
cvss distance --env "CVSS:3.1/..." "CVSS:3.1/..."

# Merge two vectors (vector2 fills missing fields in vector1)
cvss merge "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" "CVSS:3.1/E:F/RL:T/RC:C"
```

## Distance Metrics

| Metric | Description |
|--------|-------------|
| Euclidean | √(Σ(score_diff²)) — geometric distance in score-space |
| Manhattan | Σ|score_diff| — sum of absolute score differences |
| Hamming | Count of metrics with different values |
| Jaccard | Same metrics / Total metrics — similarity ratio |
| Score diff | |score1 - score2| — absolute score difference |

## Go SDK Usage

```go
cv1, _ := parser.ParseString("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
cv2, _ := parser.ParseString("CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

// Diff
diffs := cv1.Diff(cv2)
for _, d := range diffs {
    fmt.Printf("%s: %s → %s\n", d.Metric, d.V1, d.V2)
}

// Merge (non-destructive, returns new object)
merged := cv1.Merge(cv2)

// Equality
equal := cv1.Equal(cv2)

// Distance
dc := cvss.NewDistanceCalculator(cv1, cv2)
euclidean := dc.EuclideanDistance()
manhattan := dc.ManhattanDistance()
hamming := dc.HammingDistance()
jaccard := dc.JaccardSimilarity()
scoreDiff := dc.ScoreDifference()

// With environmental metrics
euclideanEnv := dc.EuclideanDistanceWithEnv()
manhattanEnv := dc.ManhattanDistanceWithEnv()

// Checked versions (return error instead of 0.0 for incomplete vectors)
dist, err := dc.EuclideanDistanceChecked()
```