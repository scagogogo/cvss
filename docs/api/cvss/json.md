# JSON Support

CVSS Skills provides comprehensive JSON serialization and deserialization support, making it easy to store, transmit, and integrate data with other systems.

## Overview

CVSS vectors support JSON through Go's standard `encoding/json` package. There are **two distinct JSON representations**, served by different APIs:

- **Vector-string form** — `json.Marshal(cvss)` / `json.Unmarshal` produce a JSON *string* whose content is the canonical vector (e.g. `"CVSS:3.1/AV:N/…"`). Compact, lossless, and the natural choice for storage and transport.
- **Structured form** — `cvss.ToJSON(calculator)` returns a `JSONOutput` object with separated scores, severities, and per-metric long values. Use this when a consumer needs the score breakdown without re-parsing or re-scoring.

Both forms round-trip cleanly; the vector-string form is the canonical serialization.

## JSON Structure

### Vector-string form (`json.Marshal`)

`Cvss3x` implements `MarshalJSON` / `UnmarshalJSON` so that the JSON value is the vector string itself:

```json
"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
```

`MarshalIndent` on a `*Cvss3x` still yields the quoted string (there is nothing to indent) — use `ToJSON` for a pretty-printed structured object.

### Structured form (`ToJSON`)

`ToJSON(calculator *Calculator) ([]byte, error)` returns indented JSON with scores and metrics already filled in. The bytes it returns are already marshaled — use them directly, do **not** pass them through `json.Marshal` again (that would base64-encode the byte slice).

For a vector with temporal metrics (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:C`):

```json
{
  "version": "3.1",
  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:C",
  "baseScore": 9.8,
  "temporalScore": 9.1,
  "baseSeverity": "Critical",
  "temporalSeverity": "Critical",
  "metrics": {
    "base": {
      "attackVector": "Network",
      "attackComplexity": "Low",
      "privilegesRequired": "None",
      "userInteraction": "None",
      "scope": "Unchanged",
      "confidentiality": "High",
      "integrity": "High",
      "availability": "High",
      "exploitabilityScore": 3.887,
      "impactScore": 5.873
    },
    "temporal": {
      "exploitCodeMaturity": "Functional",
      "remediationLevel": "Official Fix",
      "reportConfidence": "Confirmed"
    }
  }
}
```

::: tip Field names follow the spec, not the struct
Metric fields use CVSS long names (`attackVector`, `confidentiality`, `modifiedConfidentiality`, …) — there is no `Impact` suffix. Each metric value is a string long name (e.g. `"Network"`), not a nested object. Environmental metrics and `*Score` sub-scores appear only when present/computed.
:::

### Minimal base-only vector

A base-only vector (no temporal/environmental) omits those keys:

```json
{
  "version": "3.1",
  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "baseScore": 9.8,
  "baseSeverity": "Critical",
  "metrics": {
    "base": {
      "attackVector": "Network",
      "attackComplexity": "Low",
      "privilegesRequired": "None",
      "userInteraction": "None",
      "scope": "Unchanged",
      "confidentiality": "High",
      "integrity": "High",
      "availability": "High",
      "exploitabilityScore": 3.887,
      "impactScore": 5.873
    }
  }
}
```

## Serialization (Marshal)

### Vector-string form

`json.Marshal` on a `*Cvss3x` produces a JSON string whose content is the canonical vector:

```go
package main

import (
    "encoding/json"
    "fmt"
    "log"

    "github.com/scagogogo/cvss-skills/pkg/parser"
)

func main() {
    vector, err := parser.ParseString("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    if err != nil {
        log.Fatal(err)
    }

    jsonData, err := json.Marshal(vector)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println(string(jsonData))
    // "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
}
```

### Structured form (ToJSON)

For a JSON object with scores and per-metric long values, use `ToJSON`. It returns already-marshaled bytes — print or write them directly:

```go
func vectorToStructuredJSON(vector *cvss.Cvss3x) ([]byte, error) {
    calc := cvss.NewCalculator(vector)
    return vector.ToJSON(calc)
}

// Usage
out, err := vectorToStructuredJSON(vector)
if err != nil {
    log.Fatal(err)
}
fmt.Println(string(out))
```

### Pretty-printed vector string

`MarshalIndent` on a `*Cvss3x` still yields the quoted vector string (nothing to indent). If you need a pretty-printed object, use `ToJSON` (above), which already indents.

```go
func vectorToPrettyJSON(vector *cvss.Cvss3x) (string, error) {
    jsonData, err := json.MarshalIndent(vector, "", "  ")
    if err != nil {
        return "", err
    }
    return string(jsonData), nil
}
```

### Custom JSON Tags

```go
// Custom struct with specific JSON formatting
type CVSSExport struct {
    Vector      string  `json:"cvss_vector"`
    Version     string  `json:"version"`
    BaseScore   float64 `json:"base_score"`
    Severity    string  `json:"severity"`
    Timestamp   string  `json:"timestamp"`
}

func exportToCustomJSON(vector *cvss.Cvss3x) ([]byte, error) {
    calculator := cvss.NewCalculator(vector)
    score, err := calculator.Calculate()
    if err != nil {
        return nil, err
    }
    
    export := CVSSExport{
        Vector:    vector.String(),
        Version:   vector.Version(),
        BaseScore: score,
        Severity:  calculator.GetSeverityRating(score).String(),
        Timestamp: time.Now().Format(time.RFC3339),
    }
    
    return json.MarshalIndent(export, "", "  ")
}
```

## Deserialization (Unmarshal)

### Basic Deserialization

`json.Unmarshal` accepts the vector-string JSON form — the JSON value must be a quoted vector string:

```go
func vectorFromJSON(jsonData []byte) (*cvss.Cvss3x, error) {
    var vector cvss.Cvss3x
    err := json.Unmarshal(jsonData, &vector)
    if err != nil {
        return nil, fmt.Errorf("failed to unmarshal JSON: %w", err)
    }
    return &vector, nil
}

// Usage
jsonData := []byte(`"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"`)
vector, err := vectorFromJSON(jsonData)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Loaded vector: %s\n", vector.String())
```

::: warning The structured ToJSON form is not directly unmarshalable
`ToJSON`'s `JSONOutput` shape (`{"version":…,"metrics":…}`) is an output-only representation. `json.Unmarshal` into `*Cvss3x` expects the vector-string form. To reconstruct a `Cvss3x` from a `JSONOutput`, extract its `vectorString` field and unmarshal that (or `parser.ParseString` it).
:::

### Validation After Deserialization

```go
func loadAndValidateVector(jsonData []byte) (*cvss.Cvss3x, error) {
    vector, err := vectorFromJSON(jsonData)
    if err != nil {
        return nil, err
    }

    // Validate the loaded vector (Check returns a plain error for the
    // first missing/invalid metric; Validate returns structured
    // ValidationErrors for all of them).
    if err := vector.Check(); err != nil {
        return nil, fmt.Errorf("loaded vector is invalid: %w", err)
    }

    // Additional version check
    if vector.MajorVersion != 3 {
        return nil, fmt.Errorf("unsupported CVSS version: %d.%d",
            vector.MajorVersion, vector.MinorVersion)
    }

    return vector, nil
}
```

### Handling Missing Fields

```go
func loadVectorWithDefaults(jsonData []byte) (*cvss.Cvss3x, error) {
    var vector cvss.Cvss3x
    
    // Set defaults before unmarshaling
    vector.MajorVersion = 3
    vector.MinorVersion = 1
    
    err := json.Unmarshal(jsonData, &vector)
    if err != nil {
        return nil, err
    }
    
    // Fill in missing base metrics with defaults if needed
    if vector.Cvss3xBase == nil {
        return nil, fmt.Errorf("base metrics are required")
    }
    
    return &vector, nil
}
```

## File Operations

### Save to File

```go
func saveVectorToFile(vector *cvss.Cvss3x, filename string) error {
    // Use ToJSON for a pretty-printed structured object, or json.Marshal
    // for the compact vector-string form.
    jsonData, err := vector.ToJSON(cvss.NewCalculator(vector))
    if err != nil {
        return fmt.Errorf("failed to marshal vector: %w", err)
    }

    err = os.WriteFile(filename, jsonData, 0644)
    if err != nil {
        return fmt.Errorf("failed to write file: %w", err)
    }

    return nil
}

// Usage
err := saveVectorToFile(vector, "cvss_vector.json")
if err != nil {
    log.Fatal(err)
}
```

### Load from File

```go
func loadVectorFromFile(filename string) (*cvss.Cvss3x, error) {
    jsonData, err := os.ReadFile(filename)
    if err != nil {
        return nil, fmt.Errorf("failed to read file: %w", err)
    }

    return loadAndValidateVector(jsonData)
}
```

### Batch File Operations

```go
func saveVectorBatch(vectors []*cvss.Cvss3x, directory string) error {
    for i, vector := range vectors {
        filename := filepath.Join(directory, fmt.Sprintf("vector_%d.json", i+1))
        if err := saveVectorToFile(vector, filename); err != nil {
            return fmt.Errorf("failed to save vector %d: %w", i+1, err)
        }
    }
    return nil
}

func loadVectorBatch(directory string) ([]*cvss.Cvss3x, error) {
    files, err := filepath.Glob(filepath.Join(directory, "*.json"))
    if err != nil {
        return nil, err
    }
    
    var vectors []*cvss.Cvss3x
    for _, file := range files {
        vector, err := loadVectorFromFile(file)
        if err != nil {
            log.Printf("Warning: failed to load %s: %v", file, err)
            continue
        }
        vectors = append(vectors, vector)
    }
    
    return vectors, nil
}
```

## HTTP API Integration

### REST API Handler

```go
func handleCVSSVector(w http.ResponseWriter, r *http.Request) {
    switch r.Method {
    case "POST":
        // Parse vector from request body
        var request struct {
            Vector string `json:"vector"`
        }

        if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
            http.Error(w, "Invalid JSON", http.StatusBadRequest)
            return
        }

        // Parse CVSS vector
        p := parser.NewCvss3xParser(request.Vector)
        vector, err := p.Parse()
        if err != nil {
            http.Error(w, fmt.Sprintf("Parse error: %v", err), http.StatusBadRequest)
            return
        }

        // Calculate score
        calculator := cvss.NewCalculator(vector)
        score, err := calculator.Calculate()
        if err != nil {
            http.Error(w, fmt.Sprintf("Calculation error: %v", err), http.StatusInternalServerError)
            return
        }

        // Return response
        response := struct {
            Vector   *cvss.Cvss3x `json:"vector"`
            Score    float64      `json:"score"`
            Severity string       `json:"severity"`
        }{
            Vector:   vector,
            Score:    score,
            Severity: calculator.GetSeverityRating(score).String(),
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(response)

    case "GET":
        // Return example vector
        example := getExampleVector()
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(example)
    }
}
```

### JSON Schema Validation

If you must validate the structured `ToJSON` form against a schema (e.g. at an API boundary before parsing), it matches this shape:

```go
import "github.com/xeipuuv/gojsonschema"

const cvssJSONSchema = `{
  "type": "object",
  "required": ["version", "vectorString", "baseScore", "baseSeverity", "metrics"],
  "properties": {
    "version": { "type": "string", "enum": ["3.0", "3.1"] },
    "vectorString": { "type": "string" },
    "baseScore": { "type": "number", "minimum": 0, "maximum": 10 },
    "baseSeverity": { "type": "string", "enum": ["None", "Low", "Medium", "High", "Critical"] },
    "metrics": {
      "type": "object",
      "required": ["base"],
      "properties": {
        "base": {
          "type": "object",
          "required": ["attackVector", "attackComplexity", "privilegesRequired",
                       "userInteraction", "scope", "confidentiality",
                       "integrity", "availability"]
        }
      }
    }
  }
}`

func validateCVSSJSON(jsonData []byte) error {
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

::: tip Prefer parsing over schema validation
The most reliable validation is to `parser.ParseString(vectorString)` (or `json.Unmarshal` the vector-string form) and then `Check()` / `Validate()` the result. Schema validation only checks shape; the library checks CVSS semantics.
:::

## Database Integration

### SQL Database Storage

```go
import "database/sql"

func saveVectorToDB(db *sql.DB, vector *cvss.Cvss3x) error {
    jsonData, err := json.Marshal(vector)
    if err != nil {
        return err
    }
    
    query := `INSERT INTO cvss_vectors (vector_string, json_data, created_at) VALUES (?, ?, ?)`
    _, err = db.Exec(query, vector.String(), string(jsonData), time.Now())
    return err
}

func loadVectorFromDB(db *sql.DB, id int) (*cvss.Cvss3x, error) {
    var jsonData string
    query := `SELECT json_data FROM cvss_vectors WHERE id = ?`
    err := db.QueryRow(query, id).Scan(&jsonData)
    if err != nil {
        return nil, err
    }
    
    return vectorFromJSON([]byte(jsonData))
}
```

### NoSQL Database Storage

```go
import "go.mongodb.org/mongo-driver/mongo"

func saveVectorToMongo(collection *mongo.Collection, vector *cvss.Cvss3x) error {
    document := struct {
        VectorString string      `bson:"vector_string"`
        Vector       *cvss.Cvss3x `bson:"vector"`
        CreatedAt    time.Time   `bson:"created_at"`
    }{
        VectorString: vector.String(),
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
func streamVectors(vectors []*cvss.Cvss3x, w io.Writer) error {
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

### Memory-Efficient Loading

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

## Best Practices

### 1. Error Handling

```go
func safeJSONOperation(vector *cvss.Cvss3x) ([]byte, error) {
    if vector == nil {
        return nil, fmt.Errorf("vector cannot be nil")
    }

    if err := vector.Check(); err != nil {
        return nil, fmt.Errorf("vector is not valid: %w", err)
    }

    jsonData, err := json.Marshal(vector)
    if err != nil {
        return nil, fmt.Errorf("JSON marshaling failed: %w", err)
    }

    return jsonData, nil
}
```

### 2. Version Compatibility

```go
func ensureCompatibility(vector *cvss.Cvss3x) error {
    if vector.MajorVersion != 3 {
        return fmt.Errorf("unsupported major version: %d", vector.MajorVersion)
    }
    
    if vector.MinorVersion < 0 || vector.MinorVersion > 1 {
        return fmt.Errorf("unsupported minor version: %d", vector.MinorVersion)
    }
    
    return nil
}
```

### 3. Data Integrity

```go
func verifyJSONRoundTrip(original *cvss.Cvss3x) error {
    // Serialize
    jsonData, err := json.Marshal(original)
    if err != nil {
        return err
    }
    
    // Deserialize
    var restored cvss.Cvss3x
    if err := json.Unmarshal(jsonData, &restored); err != nil {
        return err
    }
    
    // Compare
    if original.String() != restored.String() {
        return fmt.Errorf("round-trip verification failed")
    }
    
    return nil
}
```

## Related Documentation

- [Cvss3x Data Structure](/api/cvss/cvss3x)
- [Calculator](/api/cvss/calculator)
- [Parser](/api/parser/cvss3x-parser)
- [Usage Examples](/examples/json)
