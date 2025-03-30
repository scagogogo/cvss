# CVSS Parser 

用Go语言实现的CVSS (Common Vulnerability Scoring System) 解析器，支持CVSS 3.x标准。

## 功能特性

- CVSS 3.x 向量字符串解析
- 基础评分 (Base Score) 计算
- 时间评分 (Temporal Score) 计算 
- 环境评分 (Environmental Score) 计算
- 严重性等级划分 (None, Low, Medium, High, Critical)
- JSON格式输出
- 向量间距离计算（欧几里得距离、曼哈顿距离、汉明距离、Jaccard相似度）
- 命令行工具支持

## 安装

### 从源码编译

```bash
# 克隆代码库
git clone https://github.com/scagogogo/cvss-parser.git
cd cvss-parser

# 编译
make build

# 或者直接安装到$GOPATH/bin
make install
```

### 使用Go安装

```bash
go install github.com/scagogogo/cvss-parser/cmd/cvss-cli@latest
```

## 命令行工具使用

```bash
# 基本用法
cvss-cli -v1 CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

# 输出详细信息
cvss-cli -v1 CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H -detailed

# 输出JSON格式
cvss-cli -v1 CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H -json

# 比较两个向量
cvss-cli -v1 CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H -v2 CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L -compare
```

### 命令行选项

| 选项 | 说明 |
|------|------|
| `-v1 <向量>` | 第一个CVSS向量字符串（必需） |
| `-v2 <向量>` | 第二个CVSS向量字符串（可选，用于比较） |
| `-json` | 输出为JSON格式 |
| `-detailed` | 显示详细评分信息 |
| `-compare` | 比较两个向量（需要-v2参数） |
| `-help` | 显示帮助信息 |

## 编程接口使用示例

### 基本解析与评分

```go
// 创建解析器
p := parser.NewCvss3xParser("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

// 解析CVSS向量
cvss3x, err := p.Parse()
if err != nil {
    log.Fatal(err)
}

// 计算评分
calculator := cvss.NewCalculator(cvss3x)
score, err := calculator.Calculate()
if err != nil {
    log.Fatal(err)
}

// 获取严重性等级
severity := calculator.GetSeverityRating(score)
fmt.Printf("CVSS评分: %.1f, 严重性: %s\n", score, severity)
```

### 转换为JSON格式

```go
// 转换为JSON格式
jsonData, err := cvss3x.ToJSON(nil)
if err != nil {
    log.Fatal(err)
}
fmt.Println(string(jsonData))
```

### 使用环境指标

```go
// 创建解析器并解析包含环境指标的CVSS向量字符串
p := parser.NewCvss3xParser("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:H/IR:M/AR:L/MAV:A/MAC:H")
cvss3x, _ := p.Parse()

// 计算评分（会自动考虑环境指标）
calculator := cvss.NewCalculator(cvss3x)
score, _ := calculator.Calculate()

fmt.Printf("CVSS评分（含环境因素）: %.1f\n", score)
```

### 向量距离计算

```go
// 准备两个CVSS向量进行比较
parser1 := parser.NewCvss3xParser("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
cvss1, _ := parser1.Parse()

parser2 := parser.NewCvss3xParser("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L") 
cvss2, _ := parser2.Parse()

// 创建距离计算器
dc := cvss.NewDistanceCalculator(cvss1, cvss2)

// 计算不同类型的距离
euclideanDist := dc.EuclideanDistance() // 欧几里得距离
manhattanDist := dc.ManhattanDistance() // 曼哈顿距离
hammingDist := dc.HammingDistance()     // 汉明距离
jaccardSim := dc.JaccardSimilarity()    // Jaccard相似度
scoreDiff := dc.ScoreDifference()       // CVSS评分差异

fmt.Printf("欧几里得距离: %.4f\n", euclideanDist)
fmt.Printf("曼哈顿距离: %.4f\n", manhattanDist)
fmt.Printf("汉明距离: %d\n", hammingDist)
fmt.Printf("Jaccard相似度: %.4f\n", jaccardSim)
fmt.Printf("CVSS评分差异: %.1f\n", scoreDiff)
```

## 待实现功能

- CVSS 4.0 支持
- 宏向量 (MacroVectors) 支持
- XML格式输出

## 参考资料
- [CVSS规范文档](https://www.first.org/cvss/specification-document)





