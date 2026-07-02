# JSON 支持

CVSS Skills 提供全面的 JSON 序列化和反序列化支持，便于数据存储、传输和与其他系统集成。

## 概述

CVSS 向量通过 Go 标准的 `encoding/json` 包支持 JSON。存在**两种截然不同的 JSON 表示**，由不同的 API 提供：

- **向量字符串形式** —— `json.Marshal(cvss)` / `json.Unmarshal` 产生一个 JSON *字符串*，其内容为规范向量（例如 `"CVSS:3.1/AV:N/…"`）。紧凑、无损，是存储和传输的自然之选。
- **结构化形式** —— `cvss.ToJSON(calculator)` 返回一个 `JSONOutput` 对象，包含已分离的评分、严重性和各指标长值。当消费方需要评分明细而又不想重新解析或重新评分时使用。

两种形式都能干净地往返；向量字符串形式是规范的序列化方式。

## JSON 结构

### 向量字符串形式（`json.Marshal`）

`Cvss3x` 实现了 `MarshalJSON` / `UnmarshalJSON`，使得 JSON 值就是向量字符串本身：

```json
"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
```

对 `*Cvss3x` 调用 `MarshalIndent` 仍然只产生这个带引号的字符串（没有任何东西需要缩进）—— 若要格式化的结构化对象，请使用 `ToJSON`。

### 结构化形式（`ToJSON`）

`ToJSON(calculator *Calculator) ([]byte, error)` 返回带缩进的 JSON，评分和指标已填充完毕。它返回的字节**已经过 marshal**——直接使用即可，**不要**再通过 `json.Marshal` 传递（那样会把 byte slice 做 base64 编码）。

对于带时间指标的向量（`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:C`）：

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

::: tip 字段名遵循规范，而非结构体
指标字段使用 CVSS 长名称（`attackVector`、`confidentiality`、`modifiedConfidentiality`……）——没有 `Impact` 后缀。每个指标值是一个字符串长名称（例如 `"Network"`），而非嵌套对象。环境指标和 `*Score` 子评分仅在存在/已计算时出现。
:::

### 最小的纯基础向量

纯基础向量（无时间/环境指标）会省略这些键：

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

## 序列化操作（Marshal）

### 向量字符串形式

对 `*Cvss3x` 调用 `json.Marshal` 产生一个 JSON 字符串，其内容为规范向量：

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

### 结构化形式（ToJSON）

若要带评分和各指标长值的 JSON 对象，请使用 `ToJSON`。它返回已经过 marshal 的字节——直接打印或写入即可：

```go
func vectorToStructuredJSON(vector *cvss.Cvss3x) ([]byte, error) {
    calc := cvss.NewCalculator(vector)
    return vector.ToJSON(calc)
}

// 用法
out, err := vectorToStructuredJSON(vector)
if err != nil {
    log.Fatal(err)
}
fmt.Println(string(out))
```

### 格式化的向量字符串

对 `*Cvss3x` 调用 `MarshalIndent` 仍然只产生带引号的向量字符串（无可缩进内容）。若需要格式化的对象，请使用上面的 `ToJSON`（它已经带缩进）。

```go
func vectorToPrettyJSON(vector *cvss.Cvss3x) (string, error) {
    jsonData, err := json.MarshalIndent(vector, "", "  ")
    if err != nil {
        return "", err
    }
    return string(jsonData), nil
}
```

### 自定义 JSON 标签

```go
// 带特定 JSON 格式的自定义结构体
type CVSSExport struct {
    Vector    string  `json:"cvss_vector"`
    Version   string  `json:"version"`
    BaseScore float64 `json:"base_score"`
    Severity  string  `json:"severity"`
    Timestamp string  `json:"timestamp"`
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

## 反序列化操作（Unmarshal）

### 基本反序列化

`json.Unmarshal` 接受向量字符串 JSON 形式——JSON 值必须是一个带引号的向量字符串：

```go
func vectorFromJSON(jsonData []byte) (*cvss.Cvss3x, error) {
    var vector cvss.Cvss3x
    err := json.Unmarshal(jsonData, &vector)
    if err != nil {
        return nil, fmt.Errorf("JSON 解组失败: %w", err)
    }
    return &vector, nil
}

// 用法
jsonData := []byte(`"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"`)
vector, err := vectorFromJSON(jsonData)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("已加载向量: %s\n", vector.String())
```

::: warning 结构化的 ToJSON 形式不能直接反序列化
`ToJSON` 的 `JSONOutput` 形状（`{"version":…,"metrics":…}`）是一个仅用于输出的表示。`json.Unmarshal` 到 `*Cvss3x` 期望的是向量字符串形式。若要从 `JSONOutput` 重构 `Cvss3x`，请提取其 `vectorString` 字段并对其进行反序列化（或用 `parser.ParseString` 解析）。
:::

### 反序列化后验证

```go
func loadAndValidateVector(jsonData []byte) (*cvss.Cvss3x, error) {
    vector, err := vectorFromJSON(jsonData)
    if err != nil {
        return nil, err
    }

    // 验证加载的向量（Check 对第一个缺失/无效的指标返回普通 error；
    // Validate 对所有指标返回结构化的 ValidationErrors）。
    if err := vector.Check(); err != nil {
        return nil, fmt.Errorf("加载的向量无效: %w", err)
    }

    // 额外的版本检查
    if vector.MajorVersion != 3 {
        return nil, fmt.Errorf("不支持的 CVSS 版本: %d.%d",
            vector.MajorVersion, vector.MinorVersion)
    }

    return vector, nil
}
```

### 处理缺失字段

```go
func loadVectorWithDefaults(jsonData []byte) (*cvss.Cvss3x, error) {
    var vector cvss.Cvss3x

    // 解组前设置默认值
    vector.MajorVersion = 3
    vector.MinorVersion = 1

    err := json.Unmarshal(jsonData, &vector)
    if err != nil {
        return nil, err
    }

    // 如有需要，用默认值填充缺失的基础指标
    if vector.Cvss3xBase == nil {
        return nil, fmt.Errorf("基础指标是必需的")
    }

    return &vector, nil
}
```

## 文件操作

### 保存到文件

```go
func saveVectorToFile(vector *cvss.Cvss3x, filename string) error {
    // 使用 ToJSON 获得格式化的结构化对象，或用 json.Marshal
    // 获得紧凑的向量字符串形式。
    jsonData, err := vector.ToJSON(cvss.NewCalculator(vector))
    if err != nil {
        return fmt.Errorf("JSON 编组失败: %w", err)
    }

    err = os.WriteFile(filename, jsonData, 0644)
    if err != nil {
        return fmt.Errorf("文件写入失败: %w", err)
    }

    return nil
}

// 用法
err := saveVectorToFile(vector, "cvss_vector.json")
if err != nil {
    log.Fatal(err)
}
```

### 从文件加载

```go
func loadVectorFromFile(filename string) (*cvss.Cvss3x, error) {
    jsonData, err := os.ReadFile(filename)
    if err != nil {
        return nil, fmt.Errorf("文件读取失败: %w", err)
    }

    return loadAndValidateVector(jsonData)
}
```

### 批量文件操作

```go
func saveVectorBatch(vectors []*cvss.Cvss3x, directory string) error {
    for i, vector := range vectors {
        filename := filepath.Join(directory, fmt.Sprintf("vector_%d.json", i+1))
        if err := saveVectorToFile(vector, filename); err != nil {
            return fmt.Errorf("保存向量 %d 失败: %w", i+1, err)
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
            log.Printf("警告: 加载 %s 失败: %v", file, err)
            continue
        }
        vectors = append(vectors, vector)
    }

    return vectors, nil
}
```

## HTTP API 集成

### REST API 处理器

```go
func handleCVSSVector(w http.ResponseWriter, r *http.Request) {
    switch r.Method {
    case "POST":
        // 从请求体解析向量
        var request struct {
            Vector string `json:"vector"`
        }

        if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
            http.Error(w, "无效的 JSON", http.StatusBadRequest)
            return
        }

        // 解析 CVSS 向量
        p := parser.NewCvss3xParser(request.Vector)
        vector, err := p.Parse()
        if err != nil {
            http.Error(w, fmt.Sprintf("解析错误: %v", err), http.StatusBadRequest)
            return
        }

        // 计算评分
        calculator := cvss.NewCalculator(vector)
        score, err := calculator.Calculate()
        if err != nil {
            http.Error(w, fmt.Sprintf("计算错误: %v", err), http.StatusInternalServerError)
            return
        }

        // 返回响应
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
        // 返回示例向量
        example := getExampleVector()
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(example)
    }
}
```

### JSON Schema 验证

若必须针对 schema 验证结构化的 `ToJSON` 形式（例如在解析前的 API 边界处），它匹配如下形状：

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
        return fmt.Errorf("验证错误: %s", strings.Join(errors, "; "))
    }

    return nil
}
```

::: tip 优先解析而非 schema 验证
最可靠的验证方式是 `parser.ParseString(vectorString)`（或对向量字符串形式 `json.Unmarshal`），然后对结果调用 `Check()` / `Validate()`。Schema 验证只检查形状；库会检查 CVSS 语义。
:::

## 数据库集成

### SQL 数据库存储

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

### NoSQL 数据库存储

```go
import "go.mongodb.org/mongo-driver/mongo"

func saveVectorToMongo(collection *mongo.Collection, vector *cvss.Cvss3x) error {
    document := struct {
        VectorString string       `bson:"vector_string"`
        Vector       *cvss.Cvss3x `bson:"vector"`
        CreatedAt    time.Time    `bson:"created_at"`
    }{
        VectorString: vector.String(),
        Vector:       vector,
        CreatedAt:    time.Now(),
    }

    _, err := collection.InsertOne(context.Background(), document)
    return err
}
```

## 性能优化

### 流式 JSON

```go
func streamVectors(vectors []*cvss.Cvss3x, w io.Writer) error {
    encoder := json.NewEncoder(w)

    // 写入数组开始
    w.Write([]byte("["))

    for i, vector := range vectors {
        if i > 0 {
            w.Write([]byte(","))
        }

        if err := encoder.Encode(vector); err != nil {
            return err
        }
    }

    // 写入数组结束
    w.Write([]byte("]"))
    return nil
}
```

### 内存高效加载

```go
func processLargeJSONFile(filename string, processor func(*cvss.Cvss3x) error) error {
    file, err := os.Open(filename)
    if err != nil {
        return err
    }
    defer file.Close()

    decoder := json.NewDecoder(file)

    // 读取开始括号
    _, err = decoder.Token()
    if err != nil {
        return err
    }

    // 处理每个向量
    for decoder.More() {
        var vector cvss.Cvss3x
        if err := decoder.Decode(&vector); err != nil {
            return err
        }

        if err := processor(&vector); err != nil {
            return err
        }
    }

    // 读取结束括号
    _, err = decoder.Token()
    return err
}
```

## 最佳实践

### 1. 错误处理

```go
func safeJSONOperation(vector *cvss.Cvss3x) ([]byte, error) {
    if vector == nil {
        return nil, fmt.Errorf("向量不能为空")
    }

    if err := vector.Check(); err != nil {
        return nil, fmt.Errorf("向量无效: %w", err)
    }

    jsonData, err := json.Marshal(vector)
    if err != nil {
        return nil, fmt.Errorf("JSON 编组失败: %w", err)
    }

    return jsonData, nil
}
```

### 2. 版本兼容性

```go
func ensureCompatibility(vector *cvss.Cvss3x) error {
    if vector.MajorVersion != 3 {
        return fmt.Errorf("不支持的主版本: %d", vector.MajorVersion)
    }

    if vector.MinorVersion < 0 || vector.MinorVersion > 1 {
        return fmt.Errorf("不支持的次版本: %d", vector.MinorVersion)
    }

    return nil
}
```

### 3. 数据完整性

```go
func verifyJSONRoundTrip(original *cvss.Cvss3x) error {
    // 序列化
    jsonData, err := json.Marshal(original)
    if err != nil {
        return err
    }

    // 反序列化
    var restored cvss.Cvss3x
    if err := json.Unmarshal(jsonData, &restored); err != nil {
        return err
    }

    // 比较
    if original.String() != restored.String() {
        return fmt.Errorf("往返验证失败")
    }

    return nil
}
```

## 相关文档

- [CVSS 数据结构](/zh/api/cvss/cvss3x) - 了解数据结构
- [Calculator 计算器](/zh/api/cvss/calculator) - 评分计算
- [Parser 解析器](/zh/api/parser/cvss3x-parser) - 向量解析
- [使用示例](/zh/examples/json) - 详细使用示例
