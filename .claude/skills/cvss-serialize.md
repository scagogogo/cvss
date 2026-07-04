# CVSS Serialize Skill

Serialize CVSS vectors to various formats: JSON, XML, vector string, map.

📖 Full documentation: https://scagogogo.github.io/cvss-skills/cli/commands/json

## CLI Command

```bash
# Structured JSON output (with scores and metric details)
cvss json "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

# Score as JSON
cvss score --format json "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
```

## Supported Formats

| Format | Method | Description |
|--------|--------|-------------|
| Vector String | `cv.String()` | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| JSON (compact) | `json.Marshal(cv)` | Quoted vector string: `"CVSS:3.1/..."` |
| JSON (structured) | `cv.ToJSON(calc)` | Full JSON with scores, severities, metric details |
| XML | `xml.Marshal(wrapper)` | Uses `MarshalText` for text content |
| Map | `cv.ToMap()` | `{"AV":"N", "AC":"L", ...}` |
| Text | `cv.MarshalText()` | Plain text vector string |

## Go SDK Usage

```go
cv, _ := parser.ParseString("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
calc := cvss.NewCalculator(cv)

// Vector string
str := cv.String()

// Compact JSON (vector string only)
data, _ := json.Marshal(cv)

// Structured JSON (with scores)
data, _ := cv.ToJSON(calc)

// XML (via TextMarshaler)
type Wrapper struct {
    XMLName xml.Name `xml:"vulnerability"`
    CVSS    *cvss.Cvss3x `xml:"cvss"`
}
data, _ := xml.Marshal(&Wrapper{CVSS: cv})

// Map
m := cv.ToMap()  // {"version":"3.1", "AV":"N", "AC":"L", ...}

// Deserialize from JSON
cv, _ := cvss.FromJSON(jsonData)

// Deserialize from text
var cv cvss.Cvss3x
cv.UnmarshalText([]byte("CVSS:3.1/AV:N/..."))

// Deserialize from map
cv, _ := cvss.FromMap(map[string]string{
    "version": "3.1",
    "AV": "N", "AC": "L", "PR": "N", "UI": "N",
    "S": "U", "C": "H", "I": "H", "A": "H",
})
```