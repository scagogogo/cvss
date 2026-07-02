# JSON 输出示例

本示例演示如何将 CVSS 向量序列化为 JSON 格式并反序列化，包括各种格式选项和集成模式。

## 概述

CVSS Skills 为以下功能提供全面的 JSON 支持：

- 将解析的向量序列化为 JSON
- 将 JSON 反序列化回向量对象
- 自定义 JSON 格式
- 与 API 和数据库集成
- JSON 批量处理

## 基本 JSON 序列化

### 简单 JSON 输出

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

### 格式化 JSON

```go
func prettyPrintJSON(vector *cvss.Cvss3x) {
    // 带缩进的格式化输出
    jsonData, err := json.MarshalIndent(vector, "", "  ")
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println("格式化 JSON:")
    fmt.Println(string(jsonData))
}
```

### 带附加信息的 JSON

```go
func enrichedJSON(vector *cvss.Cvss3x) {
    // 计算分数
    calculator := cvss.NewCalculator(vector)
    score, err := calculator.Calculate()
    if err != nil {
        log.Fatal(err)
    }

    // 创建增强结构
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

    fmt.Println("增强 JSON:")
    fmt.Println(string(jsonData))
}

func countMetrics(vector *cvss.Cvss3x) int {
    count := 8 // 基础指标
    if vector.HasTemporalMetrics() {
        count += 3
    }
    if vector.HasEnvironmentalMetrics() {
        count += 11
    }
    return count
}
```

## JSON 反序列化

### 从 JSON 加载

```go
func loadFromJSON(jsonData []byte) (*cvss.Cvss3x, error) {
    var vector cvss.Cvss3x
    err := json.Unmarshal(jsonData, &vector)
    if err != nil {
        return nil, fmt.Errorf("JSON 解组失败: %w", err)
    }

    // 验证加载的向量（Check 返回第一个缺失/无效指标）
    if err := vector.Check(); err != nil {
        return nil, fmt.Errorf("加载的向量无效: %w", err)
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

### 带错误恢复的加载

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

## 文件操作

### 保存到文件

```go
func saveToFile(vector *cvss.Cvss3x, filename string) error {
    jsonData, err := json.MarshalIndent(vector, "", "  ")
    if err != nil {
        return fmt.Errorf("JSON 编组失败: %w", err)
    }

    err = os.WriteFile(filename, jsonData, 0644)
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
    jsonData, err := os.ReadFile(filename)
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

## 自定义 JSON 格式

### 简化导出格式

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

### 详细分析格式

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

    // 如果存在时间分数，添加时间分数
    if vector.HasTemporalMetrics() {
        temporalScore, _ := calculator.GetTemporalScore()
        analysis.Scores.Temporal = temporalScore
    }

    // 如果存在环境分数，添加环境分数
    if vector.HasEnvironmentalMetrics() {
        envScore, _ := calculator.GetEnvironmentalScore()
        analysis.Scores.Environmental = envScore
    }

    return json.MarshalIndent(analysis, "", "  ")
}

func analyzeRiskFactors(vector *cvss.Cvss3x) []string {
    var factors []string
    
    if vector.Cvss3xBase.AttackVector.GetShortValue() == 'N' {
        factors = append(factors, "网络可访问")
    }
    
    if vector.Cvss3xBase.AttackComplexity.GetShortValue() == 'L' {
        factors = append(factors, "低攻击复杂度")
    }
    
    if vector.Cvss3xBase.PrivilegesRequired.GetShortValue() == 'N' {
        factors = append(factors, "无需权限")
    }
    
    if vector.Cvss3xBase.UserInteraction.GetShortValue() == 'N' {
        factors = append(factors, "无需用户交互")
    }
    
    return factors
}

func generateRecommendations(vector *cvss.Cvss3x) []string {
    var recommendations []string
    
    if vector.Cvss3xBase.AttackVector.GetShortValue() == 'N' {
        recommendations = append(recommendations, "实施网络分段")
    }
    
    if vector.Cvss3xBase.PrivilegesRequired.GetShortValue() == 'N' {
        recommendations = append(recommendations, "实施身份验证控制")
    }
    
    if vector.Cvss3xBase.Confidentiality.GetShortValue() == 'H' {
        recommendations = append(recommendations, "加密敏感数据")
    }
    
    return recommendations
}

func summarizeMetrics(vector *cvss.Cvss3x) map[string]string {
    summary := make(map[string]string)
    
    summary["攻击向量"] = vector.Cvss3xBase.AttackVector.GetLongValue()
    summary["攻击复杂度"] = vector.Cvss3xBase.AttackComplexity.GetLongValue()
    summary["所需权限"] = vector.Cvss3xBase.PrivilegesRequired.GetLongValue()
    summary["用户交互"] = vector.Cvss3xBase.UserInteraction.GetLongValue()
    summary["作用域"] = vector.Cvss3xBase.Scope.GetLongValue()
    summary["机密性"] = vector.Cvss3xBase.Confidentiality.GetLongValue()
    summary["完整性"] = vector.Cvss3xBase.Integrity.GetLongValue()
    summary["可用性"] = vector.Cvss3xBase.Availability.GetLongValue()
    
    return summary
}
```

## API 集成

### REST API 处理器

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
        vector, err := parser.ParseString(request.Vector)
        if err != nil {
            http.Error(w, fmt.Sprintf("解析错误: %v", err), http.StatusBadRequest)
            return
        }

        // 根据格式生成响应
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
            result["severity"] = calculator.GetSeverityRating(score).String()
        default:
            result["parsed"] = vector
            result["score"] = score
            result["severity"] = calculator.GetSeverityRating(score).String()
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
        calculator.GetSeverityRating(score).String(),
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

### NoSQL 数据库存储

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
        Severity:     calculator.GetSeverityRating(score).String(),
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

## 测试和验证

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

## 下一步

掌握 JSON 操作后，您可以探索：

- [距离计算](/zh/examples/distance) - 比较向量
- [时间指标](/zh/examples/temporal) - 基于时间的评分
- [高级示例](/zh/examples/edge-cases) - 复杂场景

## 相关文档

- [JSON API 参考](/zh/api/cvss/json) - 详细的 JSON 文档
- [CVSS 数据结构](/zh/api/cvss/cvss3x) - 理解数据格式
- [数据库集成指南](/zh/api/getting-started) - 生产环境集成模式
