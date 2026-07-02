# JSON Output Examples

This example demonstrates how to serialize CVSS vectors to JSON format and deserialize them back, including various formatting options and integration patterns.

## Overview

CVSS Skills provides comprehensive JSON support for:

- Serializing parsed vectors to JSON
- Deserializing JSON back to vector objects
- Custom JSON formatting
- Integration with APIs and databases
- Batch processing with JSON

## Basic JSON Serialization

### Simple JSON Output

```go
package main

import (
    "encoding/json"
    "fmt"
    "log"

    "github.com/scagogogo/cvss-skills/pkg/cvss"
    "github.com/scagogogo/cvss-skills/pkg/parser"
)

func main() {
    // Parse CVSS vector
    vectorStr := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    p := parser.NewCvss3xParser(vectorStr)
    vector, err := p.Parse()
    if err != nil {
        log.Fatal(err)
    }

    // Serialize to JSON
    jsonData, err := json.Marshal(vector)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println("Compact JSON:")
    fmt.Println(string(jsonData))
}
```

### Pretty-Printed JSON

```go
func prettyPrintJSON(vector *cvss.Cvss3x) {
    // Pretty-print with indentation
    jsonData, err := json.MarshalIndent(vector, "", "  ")
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println("Pretty JSON:")
    fmt.Println(string(jsonData))
}
```

### JSON with Additional Information

```go
func enrichedJSON(vector *cvss.Cvss3x) {
    // Calculate score
    calculator := cvss.NewCalculator(vector)
    score, err := calculator.Calculate()
    if err != nil {
        log.Fatal(err)
    }

    // Create enriched structure
    enriched := struct {
        Vector    *cvss.Cvss3x `json:"vector"`
        Score     float64      `json:"score"`
        Severity  string       `json:"severity"`
        Timestamp string       `json:"timestamp"`
        Metadata  struct {
            HasTemporal      bool `json:"hasTemporal"`
            HasEnvironmental bool `json:"hasEnvironmental"`
            MetricCount      int  `json:"metricCount"`
        } `json:"metadata"`
    }{
        Vector:    vector,
        Score:     score,
        Severity:  calculator.GetSeverityRating(score).String(),
        Timestamp: time.Now().Format(time.RFC3339),
    }

    enriched.Metadata.HasTemporal = vector.HasTemporalMetrics()
    enriched.Metadata.HasEnvironmental = vector.HasEnvironmentalMetrics()
    enriched.Metadata.MetricCount = countMetrics(vector)

    jsonData, err := json.MarshalIndent(enriched, "", "  ")
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println("Enriched JSON:")
    fmt.Println(string(jsonData))
}

func countMetrics(vector *cvss.Cvss3x) int {
    count := 8 // Base metrics
    if vector.HasTemporalMetrics() {
        count += 3
    }
    if vector.HasEnvironmentalMetrics() {
        count += 11
    }
    return count
}
```

## JSON Deserialization

### Loading from JSON

```go
func loadFromJSON(jsonData []byte) (*cvss.Cvss3x, error) {
    var vector cvss.Cvss3x
    err := json.Unmarshal(jsonData, &vector)
    if err != nil {
        return nil, fmt.Errorf("failed to unmarshal JSON: %w", err)
    }

    // Validate loaded vector (Check returns the first missing/invalid metric)
    if err := vector.Check(); err != nil {
        return nil, fmt.Errorf("loaded vector is invalid: %w", err)
    }

    return &vector, nil
}
```

### Round-Trip Validation

```go
func validateRoundTrip(original *cvss.Cvss3x) error {
    // Serialize to JSON
    jsonData, err := json.Marshal(original)
    if err != nil {
        return fmt.Errorf("serialization failed: %w", err)
    }

    // Deserialize back
    restored, err := loadFromJSON(jsonData)
    if err != nil {
        return fmt.Errorf("deserialization failed: %w", err)
    }

    // Compare vector strings
    if original.String() != restored.String() {
        return fmt.Errorf("round-trip validation failed: %s != %s", 
            original.String(), restored.String())
    }

    fmt.Println("✓ Round-trip validation successful")
    return nil
}
```

### Loading with Error Recovery

```go
func safeLoadFromJSON(jsonData []byte) (*cvss.Cvss3x, error) {
    var vector cvss.Cvss3x

    // Set defaults before unmarshaling
    vector.MajorVersion = 3
    vector.MinorVersion = 1

    err := json.Unmarshal(jsonData, &vector)
    if err != nil {
        return nil, fmt.Errorf("JSON unmarshal failed: %w", err)
    }

    // Post-load validation
    if vector.MajorVersion != 3 {
        return nil, fmt.Errorf("unsupported CVSS version: %d.%d", 
            vector.MajorVersion, vector.MinorVersion)
    }

    if vector.Cvss3xBase == nil {
        return nil, fmt.Errorf("missing base metrics")
    }

    return &vector, nil
}
```

## File Operations

### Save to File

```go
func saveToFile(vector *cvss.Cvss3x, filename string) error {
    jsonData, err := json.MarshalIndent(vector, "", "  ")
    if err != nil {
        return fmt.Errorf("JSON marshal failed: %w", err)
    }

    err = os.WriteFile(filename, jsonData, 0644)
    if err != nil {
        return fmt.Errorf("file write failed: %w", err)
    }

    fmt.Printf("Vector saved to %s\n", filename)
    return nil
}
```

### Load from File

```go
func loadFromFile(filename string) (*cvss.Cvss3x, error) {
    jsonData, err := os.ReadFile(filename)
    if err != nil {
        return nil, fmt.Errorf("file read failed: %w", err)
    }

    return safeLoadFromJSON(jsonData)
}
```

### Batch File Operations

```go
func saveBatchToFiles(vectors []*cvss.Cvss3x, directory string) error {
    // Create directory if it doesn't exist
    err := os.MkdirAll(directory, 0755)
    if err != nil {
        return err
    }

    for i, vector := range vectors {
        filename := filepath.Join(directory, fmt.Sprintf("vector_%03d.json", i+1))
        if err := saveToFile(vector, filename); err != nil {
            return fmt.Errorf("failed to save vector %d: %w", i+1, err)
        }
    }

    fmt.Printf("Saved %d vectors to %s\n", len(vectors), directory)
    return nil
}

func loadBatchFromFiles(directory string) ([]*cvss.Cvss3x, error) {
    files, err := filepath.Glob(filepath.Join(directory, "*.json"))
    if err != nil {
        return nil, err
    }

    var vectors []*cvss.Cvss3x
    for _, file := range files {
        vector, err := loadFromFile(file)
        if err != nil {
            fmt.Printf("Warning: failed to load %s: %v\n", file, err)
            continue
        }
        vectors = append(vectors, vector)
    }

    fmt.Printf("Loaded %d vectors from %s\n", len(vectors), directory)
    return vectors, nil
}
```

## Custom JSON Formats

### Simplified Export Format

```go
type SimplifiedVector struct {
    Vector   string  `json:"cvss_vector"`
    Version  string  `json:"version"`
    Score    float64 `json:"base_score"`
    Severity string  `json:"severity"`
}

func exportSimplified(vector *cvss.Cvss3x) ([]byte, error) {
    calculator := cvss.NewCalculator(vector)
    score, err := calculator.Calculate()
    if err != nil {
        return nil, err
    }

    simplified := SimplifiedVector{
        Vector:   vector.String(),
        Version:  vector.Version(),
        Score:    score,
        Severity: calculator.GetSeverityRating(score).String(),
    }

    return json.MarshalIndent(simplified, "", "  ")
}
```

### Detailed Analysis Format

```go
type DetailedAnalysis struct {
    Vector      *cvss.Cvss3x `json:"vector"`
    Scores      ScoreBreakdown `json:"scores"`
    Analysis    VectorAnalysis `json:"analysis"`
    Timestamp   string `json:"timestamp"`
}

type ScoreBreakdown struct {
    Base         float64 `json:"base"`
    Temporal     float64 `json:"temporal,omitempty"`
    Environmental float64 `json:"environmental,omitempty"`
    Final        float64 `json:"final"`
}

type VectorAnalysis struct {
    Severity        string   `json:"severity"`
    RiskFactors     []string `json:"risk_factors"`
    Recommendations []string `json:"recommendations"`
    MetricSummary   map[string]string `json:"metric_summary"`
}

func exportDetailedAnalysis(vector *cvss.Cvss3x) ([]byte, error) {
    calculator := cvss.NewCalculator(vector)
    
    baseScore, _ := calculator.GetBaseScore()
    finalScore, _ := calculator.Calculate()
    
    analysis := DetailedAnalysis{
        Vector: vector,
        Scores: ScoreBreakdown{
            Base:  baseScore,
            Final: finalScore,
        },
        Analysis: VectorAnalysis{
            Severity:      calculator.GetSeverityRating(finalScore).String(),
            RiskFactors:   analyzeRiskFactors(vector),
            Recommendations: generateRecommendations(vector),
            MetricSummary: summarizeMetrics(vector),
        },
        Timestamp: time.Now().Format(time.RFC3339),
    }

    // Add temporal score if present
    if vector.HasTemporalMetrics() {
        temporalScore, _ := calculator.GetTemporalScore()
        analysis.Scores.Temporal = temporalScore
    }

    // Add environmental score if present
    if vector.HasEnvironmentalMetrics() {
        envScore, _ := calculator.GetEnvironmentalScore()
        analysis.Scores.Environmental = envScore
    }

    return json.MarshalIndent(analysis, "", "  ")
}

func analyzeRiskFactors(vector *cvss.Cvss3x) []string {
    var factors []string
    
    if vector.Cvss3xBase.AttackVector.GetShortValue() == 'N' {
        factors = append(factors, "Network accessible")
    }
    
    if vector.Cvss3xBase.AttackComplexity.GetShortValue() == 'L' {
        factors = append(factors, "Low attack complexity")
    }
    
    if vector.Cvss3xBase.PrivilegesRequired.GetShortValue() == 'N' {
        factors = append(factors, "No privileges required")
    }
    
    if vector.Cvss3xBase.UserInteraction.GetShortValue() == 'N' {
        factors = append(factors, "No user interaction required")
    }
    
    return factors
}

func generateRecommendations(vector *cvss.Cvss3x) []string {
    var recommendations []string
    
    if vector.Cvss3xBase.AttackVector.GetShortValue() == 'N' {
        recommendations = append(recommendations, "Implement network segmentation")
    }
    
    if vector.Cvss3xBase.PrivilegesRequired.GetShortValue() == 'N' {
        recommendations = append(recommendations, "Implement authentication controls")
    }
    
    if vector.Cvss3xBase.Confidentiality.GetShortValue() == 'H' {
        recommendations = append(recommendations, "Encrypt sensitive data")
    }
    
    return recommendations
}

func summarizeMetrics(vector *cvss.Cvss3x) map[string]string {
    summary := make(map[string]string)
    
    summary["Attack Vector"] = vector.Cvss3xBase.AttackVector.GetLongValue()
    summary["Attack Complexity"] = vector.Cvss3xBase.AttackComplexity.GetLongValue()
    summary["Privileges Required"] = vector.Cvss3xBase.PrivilegesRequired.GetLongValue()
    summary["User Interaction"] = vector.Cvss3xBase.UserInteraction.GetLongValue()
    summary["Scope"] = vector.Cvss3xBase.Scope.GetLongValue()
    summary["Confidentiality"] = vector.Cvss3xBase.Confidentiality.GetLongValue()
    summary["Integrity"] = vector.Cvss3xBase.Integrity.GetLongValue()
    summary["Availability"] = vector.Cvss3xBase.Availability.GetLongValue()
    
    return summary
}
```

## API Integration

### REST API Handler

```go
func handleVectorAnalysis(w http.ResponseWriter, r *http.Request) {
    switch r.Method {
    case "POST":
        var request struct {
            Vector string `json:"vector"`
            Format string `json:"format,omitempty"`
        }

        if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
            http.Error(w, "Invalid JSON", http.StatusBadRequest)
            return
        }

        // Parse vector
        vector, err := parser.ParseString(request.Vector)
        if err != nil {
            http.Error(w, fmt.Sprintf("Parse error: %v", err), http.StatusBadRequest)
            return
        }

        // Generate response based on format
        var responseData []byte
        switch request.Format {
        case "detailed":
            responseData, err = exportDetailedAnalysis(vector)
        case "simplified":
            responseData, err = exportSimplified(vector)
        default:
            responseData, err = json.MarshalIndent(vector, "", "  ")
        }

        if err != nil {
            http.Error(w, fmt.Sprintf("Export error: %v", err), http.StatusInternalServerError)
            return
        }

        w.Header().Set("Content-Type", "application/json")
        w.Write(responseData)

    default:
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
    }
}
```

### Batch API Handler

```go
func handleBatchAnalysis(w http.ResponseWriter, r *http.Request) {
    var request struct {
        Vectors []string `json:"vectors"`
        Format  string   `json:"format,omitempty"`
    }

    if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
        http.Error(w, "Invalid JSON", http.StatusBadRequest)
        return
    }

    var results []interface{}

    for i, vectorStr := range request.Vectors {
        result := map[string]interface{}{
            "index":  i,
            "vector": vectorStr,
        }

        vector, err := parser.ParseString(vectorStr)
        if err != nil {
            result["error"] = err.Error()
            results = append(results, result)
            continue
        }

        calculator := cvss.NewCalculator(vector)
        score, _ := calculator.Calculate()

        switch request.Format {
        case "simplified":
            result["score"] = score
            result["severity"] = calculator.GetSeverityRating(score)
        default:
            result["parsed"] = vector
            result["score"] = score
            result["severity"] = calculator.GetSeverityRating(score)
        }

        results = append(results, result)
    }

    response := map[string]interface{}{
        "results": results,
        "total":   len(request.Vectors),
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}
```

## Database Integration

### SQL Database Storage

```go
func saveVectorToDB(db *sql.DB, vector *cvss.Cvss3x) error {
    calculator := cvss.NewCalculator(vector)
    score, err := calculator.Calculate()
    if err != nil {
        return err
    }

    jsonData, err := json.Marshal(vector)
    if err != nil {
        return err
    }

    query := `
        INSERT INTO cvss_vectors (
            vector_string, 
            score, 
            severity, 
            json_data, 
            created_at
        ) VALUES (?, ?, ?, ?, ?)
    `

    _, err = db.Exec(query,
        vector.String(),
        score,
        calculator.GetSeverityRating(score),
        string(jsonData),
        time.Now(),
    )

    return err
}

func loadVectorFromDB(db *sql.DB, id int) (*cvss.Cvss3x, error) {
    var jsonData string
    query := `SELECT json_data FROM cvss_vectors WHERE id = ?`
    
    err := db.QueryRow(query, id).Scan(&jsonData)
    if err != nil {
        return nil, err
    }

    return safeLoadFromJSON([]byte(jsonData))
}
```

### NoSQL Database Storage

```go
func saveVectorToMongo(collection *mongo.Collection, vector *cvss.Cvss3x) error {
    calculator := cvss.NewCalculator(vector)
    score, _ := calculator.Calculate()

    document := struct {
        VectorString string      `bson:"vector_string"`
        Score        float64     `bson:"score"`
        Severity     string      `bson:"severity"`
        Vector       *cvss.Cvss3x `bson:"vector"`
        CreatedAt    time.Time   `bson:"created_at"`
    }{
        VectorString: vector.String(),
        Score:        score,
        Severity:     calculator.GetSeverityRating(score),
        Vector:       vector,
        CreatedAt:    time.Now(),
    }

    _, err := collection.InsertOne(context.Background(), document)
    return err
}
```

## Performance Optimization

### Streaming JSON

```go
func streamVectorsToJSON(vectors []*cvss.Cvss3x, w io.Writer) error {
    encoder := json.NewEncoder(w)

    // Write array start
    w.Write([]byte("["))

    for i, vector := range vectors {
        if i > 0 {
            w.Write([]byte(","))
        }

        if err := encoder.Encode(vector); err != nil {
            return err
        }
    }

    // Write array end
    w.Write([]byte("]"))
    return nil
}
```

### Memory-Efficient Processing

```go
func processLargeJSONFile(filename string, processor func(*cvss.Cvss3x) error) error {
    file, err := os.Open(filename)
    if err != nil {
        return err
    }
    defer file.Close()

    decoder := json.NewDecoder(file)

    // Read opening bracket
    _, err = decoder.Token()
    if err != nil {
        return err
    }

    // Process each vector
    for decoder.More() {
        var vector cvss.Cvss3x
        if err := decoder.Decode(&vector); err != nil {
            return err
        }

        if err := processor(&vector); err != nil {
            return err
        }
    }

    // Read closing bracket
    _, err = decoder.Token()
    return err
}
```

## Testing and Validation

### JSON Schema Validation

```go
const cvssJSONSchema = `{
  "type": "object",
  "required": ["majorVersion", "minorVersion", "base"],
  "properties": {
    "majorVersion": {"type": "integer", "enum": [3]},
    "minorVersion": {"type": "integer", "enum": [0, 1]},
    "base": {"type": "object"}
  }
}`

func validateJSONSchema(jsonData []byte) error {
    schemaLoader := gojsonschema.NewStringLoader(cvssJSONSchema)
    documentLoader := gojsonschema.NewBytesLoader(jsonData)

    result, err := gojsonschema.Validate(schemaLoader, documentLoader)
    if err != nil {
        return err
    }

    if !result.Valid() {
        var errors []string
        for _, desc := range result.Errors() {
            errors = append(errors, desc.String())
        }
        return fmt.Errorf("validation errors: %s", strings.Join(errors, "; "))
    }

    return nil
}
```

## Next Steps

After mastering JSON operations, you can explore:

- [Distance Calculation](/examples/distance) - Comparing vectors
- [Temporal Metrics](/examples/temporal) - Time-based scoring
- [Advanced Examples](/examples/edge-cases) - Complex scenarios

## Related Documentation

- [JSON API Reference](/api/cvss/json) - Detailed JSON documentation
- [CVSS Data Structures](/api/cvss/cvss3x) - Understanding data formats
- [Database Integration Guide](/api/getting-started) - Production integration patterns
