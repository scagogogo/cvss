# JSON 支持

CVSS Skills 提供全面的 JSON 序列化和反序列化支持，便于数据存储、传输和与其他系统集成。

## 概述

所有 CVSS 数据结构都通过 Go 标准的 `encoding/json` 包实现 JSON 编组和解组。JSON 格式设计为：

- **人类可读**: 清晰的字段名称和结构
- **紧凑**: 省略空的可选字段
- **互操作**: 与其他 CVSS 实现兼容
- **版本化**: 包含版本信息以确保兼容性

## JSON 结构

### 完整的 CVSS 向量 JSON

```json
{
  "majorVersion": 3,
  "minorVersion": 1,
  "base": {
    "attackVector": {
      "shortName": "AV",
      "shortValue": "N",
      "longValue": "Network",
      "score": 0.85
    },
    "attackComplexity": {
      "shortName": "AC",
      "shortValue": "L",
      "longValue": "Low",
      "score": 0.77
    },
    "privilegesRequired": {
      "shortName": "PR",
      "shortValue": "N",
      "longValue": "None",
      "score": 0.85
    },
    "userInteraction": {
      "shortName": "UI",
      "shortValue": "N",
      "longValue": "None",
      "score": 0.85
    },
    "scope": {
      "shortName": "S",
      "shortValue": "U",
      "longValue": "Unchanged",
      "score": 1.0
    },
    "confidentialityImpact": {
      "shortName": "C",
      "shortValue": "H",
      "longValue": "High",
      "score": 0.56
    },
    "integrityImpact": {
      "shortName": "I",
      "shortValue": "H",
      "longValue": "High",
      "score": 0.56
    },
    "availabilityImpact": {
      "shortName": "A",
      "shortValue": "H",
      "longValue": "High",
      "score": 0.56
    }
  }
}
```

### 带时间指标的 JSON

```json
{
  "majorVersion": 3,
  "minorVersion": 1,
  "base": { /* 基础指标 */ },
  "temporal": {
    "exploitCodeMaturity": {
      "shortName": "E",
      "shortValue": "F",
      "longValue": "Functional",
      "score": 0.97
    },
    "remediationLevel": {
      "shortName": "RL",
      "shortValue": "O",
      "longValue": "Official Fix",
      "score": 0.95
    },
    "reportConfidence": {
      "shortName": "RC",
      "shortValue": "C",
      "longValue": "Confirmed",
      "score": 1.0
    }
  }
}
```

### 带环境指标的 JSON

```json
{
  "majorVersion": 3,
  "minorVersion": 1,
  "base": { /* 基础指标 */ },
  "environmental": {
    "confidentialityRequirement": {
      "shortName": "CR",
      "shortValue": "H",
      "longValue": "High",
      "score": 1.5
    },
    "integrityRequirement": {
      "shortName": "IR",
      "shortValue": "H",
      "longValue": "High",
      "score": 1.5
    },
    "availabilityRequirement": {
      "shortName": "AR",
      "shortValue": "H",
      "longValue": "High",
      "score": 1.5
    },
    "modifiedAttackVector": {
      "shortName": "MAV",
      "shortValue": "L",
      "longValue": "Local",
      "score": 0.62
    }
  }
}
```

## 序列化操作

### 基本序列化

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
    // 解析 CVSS 向量
    vectorStr := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    p := parser.NewCvss3xParser(vectorStr)
    vector, err := p.Parse()
    if err != nil {
        log.Fatal(err)
    }

    // 序列化为 JSON
    jsonData, err := json.Marshal(vector)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println("紧凑 JSON:")
    fmt.Println(string(jsonData))
}
```

### 格式化输出

```go
func prettyPrintJSON(vector *cvss.Cvss3x) {
    // 格式化输出，带缩进
    jsonData, err := json.MarshalIndent(vector, "", "  ")
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println("格式化 JSON:")
    fmt.Println(string(jsonData))
}
```

### 自定义 JSON 格式

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
        Version:  vector.GetVersion(),
        Score:    score,
        Severity: calculator.GetSeverityRating(score),
    }

    return json.MarshalIndent(simplified, "", "  ")
}
```

## 反序列化操作

### 基本反序列化

```go
func loadFromJSON(jsonData []byte) (*cvss.Cvss3x, error) {
    var vector cvss.Cvss3x
    err := json.Unmarshal(jsonData, &vector)
    if err != nil {
        return nil, fmt.Errorf("JSON 解组失败: %w", err)
    }

    // 验证加载的向量
    if !vector.IsValid() {
        return nil, fmt.Errorf("加载的向量无效")
    }

    return &vector, nil
}
```

### 安全反序列化

```go
func safeLoadFromJSON(jsonData []byte) (*cvss.Cvss3x, error) {
    var vector cvss.Cvss3x

    // 解组前设置默认值
    vector.MajorVersion = 3
    vector.MinorVersion = 1

    err := json.Unmarshal(jsonData, &vector)
    if err != nil {
        return nil, fmt.Errorf("JSON 解组失败: %w", err)
    }

    // 加载后验证
    if vector.MajorVersion != 3 {
        return nil, fmt.Errorf("不支持的 CVSS 版本: %d.%d", 
            vector.MajorVersion, vector.MinorVersion)
    }

    if vector.Cvss3xBase == nil {
        return nil, fmt.Errorf("缺少基础指标")
    }

    return &vector, nil
}
```

### 往返验证

```go
func validateRoundTrip(original *cvss.Cvss3x) error {
    // 序列化为 JSON
    jsonData, err := json.Marshal(original)
    if err != nil {
        return fmt.Errorf("序列化失败: %w", err)
    }

    // 反序列化回来
    restored, err := loadFromJSON(jsonData)
    if err != nil {
        return fmt.Errorf("反序列化失败: %w", err)
    }

    // 比较向量字符串
    if original.String() != restored.String() {
        return fmt.Errorf("往返验证失败: %s != %s", 
            original.String(), restored.String())
    }

    fmt.Println("✓ 往返验证成功")
    return nil
}
```

## 文件操作

### 保存到文件

```go
func saveToFile(vector *cvss.Cvss3x, filename string) error {
    jsonData, err := json.MarshalIndent(vector, "", "  ")
    if err != nil {
        return fmt.Errorf("JSON 编组失败: %w", err)
    }

    err = ioutil.WriteFile(filename, jsonData, 0644)
    if err != nil {
        return fmt.Errorf("文件写入失败: %w", err)
    }

    fmt.Printf("向量已保存到 %s\n", filename)
    return nil
}
```

### 从文件加载

```go
func loadFromFile(filename string) (*cvss.Cvss3x, error) {
    jsonData, err := ioutil.ReadFile(filename)
    if err != nil {
        return nil, fmt.Errorf("文件读取失败: %w", err)
    }

    return safeLoadFromJSON(jsonData)
}
```

### 批量文件操作

```go
func saveBatchToFiles(vectors []*cvss.Cvss3x, directory string) error {
    // 创建目录（如果不存在）
    err := os.MkdirAll(directory, 0755)
    if err != nil {
        return err
    }

    for i, vector := range vectors {
        filename := filepath.Join(directory, fmt.Sprintf("vector_%03d.json", i+1))
        if err := saveToFile(vector, filename); err != nil {
            return fmt.Errorf("保存向量 %d 失败: %w", i+1, err)
        }
    }

    fmt.Printf("已保存 %d 个向量到 %s\n", len(vectors), directory)
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
            fmt.Printf("警告: 加载 %s 失败: %v\n", file, err)
            continue
        }
        vectors = append(vectors, vector)
    }

    fmt.Printf("从 %s 加载了 %d 个向量\n", directory, len(vectors))
    return vectors, nil
}
```

## API 集成

### HTTP API 处理器

```go
func handleVectorAnalysis(w http.ResponseWriter, r *http.Request) {
    switch r.Method {
    case "POST":
        var request struct {
            Vector string `json:"vector"`
            Format string `json:"format,omitempty"`
        }

        if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
            http.Error(w, "无效的 JSON", http.StatusBadRequest)
            return
        }

        // 解析向量
        parser := parser.NewCvss3xParser(request.Vector)
        vector, err := parser.Parse()
        if err != nil {
            http.Error(w, fmt.Sprintf("解析错误: %v", err), http.StatusBadRequest)
            return
        }

        // 根据格式生成响应
        var responseData []byte
        switch request.Format {
        case "simplified":
            responseData, err = exportSimplified(vector)
        default:
            responseData, err = json.MarshalIndent(vector, "", "  ")
        }

        if err != nil {
            http.Error(w, fmt.Sprintf("导出错误: %v", err), http.StatusInternalServerError)
            return
        }

        w.Header().Set("Content-Type", "application/json")
        w.Write(responseData)

    default:
        http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
    }
}
```

### 批量 API 处理器

```go
func handleBatchAnalysis(w http.ResponseWriter, r *http.Request) {
    var request struct {
        Vectors []string `json:"vectors"`
        Format  string   `json:"format,omitempty"`
    }

    if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
        http.Error(w, "无效的 JSON", http.StatusBadRequest)
        return
    }

    var results []interface{}

    for i, vectorStr := range request.Vectors {
        result := map[string]interface{}{
            "index":  i,
            "vector": vectorStr,
        }

        parser := parser.NewCvss3xParser(vectorStr)
        vector, err := parser.Parse()
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

## 数据库集成

### SQL 数据库存储

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

## 性能优化

### 流式 JSON

```go
func streamVectorsToJSON(vectors []*cvss.Cvss3x, w io.Writer) error {
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

### 内存高效处理

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

### JSON 模式验证

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
        return fmt.Errorf("验证错误: %s", strings.Join(errors, "; "))
    }

    return nil
}
```

### 错误处理

```go
func robustJSONProcessing(jsonData []byte) (*cvss.Cvss3x, error) {
    // 输入验证
    if len(jsonData) == 0 {
        return nil, fmt.Errorf("JSON 数据为空")
    }

    if len(jsonData) > 1024*1024 { // 1MB 限制
        return nil, fmt.Errorf("JSON 数据过大: %d 字节", len(jsonData))
    }

    // 模式验证
    if err := validateJSONSchema(jsonData); err != nil {
        return nil, fmt.Errorf("模式验证失败: %w", err)
    }

    // 安全加载
    vector, err := safeLoadFromJSON(jsonData)
    if err != nil {
        return nil, fmt.Errorf("加载失败: %w", err)
    }

    return vector, nil
}
```

## 相关文档

- [CVSS 数据结构](/zh/api/cvss/cvss3x) - 了解数据结构
- [JSON 示例](/zh/examples/json) - 详细使用示例
- [API 集成指南](/zh/api/getting-started) - 生产环境集成模式
