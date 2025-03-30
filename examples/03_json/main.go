package main

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/scagogogo/cvss-parser/pkg/cvss"
	"github.com/scagogogo/cvss-parser/pkg/parser"
	"github.com/scagogogo/cvss-parser/pkg/vector"
)

func main() {
	// =====================================================
	// CVSS JSON格式输出示例
	// 展示如何将CVSS向量转换为JSON格式，并演示不同类型向量的JSON表示
	// =====================================================

	fmt.Println("CVSS JSON格式输出示例")
	fmt.Println("=====================================================")

	// 例1：基础向量的JSON输出
	fmt.Println("\n1. 基础向量的JSON输出:")
	demoJsonOutput("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

	// 例2：带时间指标的向量JSON输出
	fmt.Println("\n2. 带时间指标的向量JSON输出:")
	demoJsonOutput("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:C")

	// 例3：带环境指标的向量JSON输出
	fmt.Println("\n3. 带环境指标的向量JSON输出:")
	demoJsonOutput("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:H/IR:M/AR:L")

	// 例4：带修改环境指标的向量JSON输出
	fmt.Println("\n4. 带修改环境指标的向量JSON输出:")
	demoJsonOutput("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:H/IR:M/AR:L/MAV:P/MAC:H")

	// 例5：完整包含所有可能指标的向量JSON输出
	fmt.Println("\n5. 完整包含所有可能指标的向量JSON输出:")
	demoJsonOutput("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:C/CR:H/IR:M/AR:L/MAV:L/MAC:H/MPR:L/MUI:R/MS:C/MC:L/MI:L/MA:L")

	// 例6：手动构建CVSS对象并转换为JSON
	fmt.Println("\n6. 手动构建CVSS对象并转换为JSON:")
	demoManualJsonOutput()

	fmt.Println("\n=====================================================")
	fmt.Println("CVSS JSON格式输出示例结束")
}

// 演示将CVSS向量转换为JSON并美化输出
func demoJsonOutput(vectorStr string) {
	fmt.Printf("CVSS向量: %s\n", vectorStr)

	// 解析向量
	p := parser.NewCvss3xParser(vectorStr)
	cvss3x, err := p.Parse()
	if err != nil {
		log.Printf("解析失败: %v\n", err)
		return
	}

	// 转换为JSON格式
	jsonData, err := cvss3x.ToJSON(nil)
	if err != nil {
		log.Printf("转换为JSON失败: %v\n", err)
		return
	}

	// 创建计算器计算评分
	calculator := cvss.NewCalculator(cvss3x)
	score, _ := calculator.Calculate()

	// 获取严重性
	severity := calculator.GetSeverityRating(score)
	fmt.Printf("评分: %.1f, 严重性: %s\n", score, severity)

	// 打印格式化后的JSON字符串
	var prettyJSON map[string]interface{}
	err = json.Unmarshal(jsonData, &prettyJSON)
	if err != nil {
		log.Printf("JSON格式化失败: %v\n", err)
		fmt.Println(string(jsonData))
		return
	}

	// 高亮显示一些关键JSON字段
	fmt.Println("JSON输出 (展示部分关键字段):")
	fmt.Printf("  版本: %s\n", prettyJSON["version"])
	fmt.Printf("  评分: %.1f (%s)\n",
		prettyJSON["baseScore"].(float64),
		prettyJSON["baseSeverity"].(string))

	// 检查并打印时间评分
	if temporal, ok := prettyJSON["temporalScore"]; ok {
		fmt.Printf("  时间评分: %.1f (%s)\n",
			temporal.(float64),
			prettyJSON["temporalSeverity"].(string))
	}

	// 检查并打印环境评分
	if env, ok := prettyJSON["environmentalScore"]; ok {
		fmt.Printf("  环境评分: %.1f (%s)\n",
			env.(float64),
			prettyJSON["environmentalSeverity"].(string))
	}

	// 打印完整JSON
	fmt.Println("完整JSON输出:")
	prettyJSONBytes, _ := json.MarshalIndent(prettyJSON, "", "  ")
	fmt.Println(string(prettyJSONBytes))
}

// 演示手动构建CVSS对象并转换为JSON
func demoManualJsonOutput() {
	// 创建一个新的CVSS 3.1对象
	cvss3x := cvss.NewCvss3x()
	cvss3x.MajorVersion = 3
	cvss3x.MinorVersion = 1

	// 填充基础字段
	cvss3x.Cvss3xBase = &cvss.Cvss3xBase{
		AttackVector:       vector.AttackVectorNetwork,    // 网络攻击
		AttackComplexity:   vector.AttackComplexityLow,    // 低复杂度
		PrivilegesRequired: vector.PrivilegesRequiredNone, // 无需权限
		UserInteraction:    vector.UserInteractionNone,    // 无需用户交互
		Scope:              vector.ScopeUnchanged,         // 范围不变
		Confidentiality:    vector.ConfidentialityHigh,    // 高机密性影响
		Integrity:          vector.IntegrityHigh,          // 高完整性影响
		Availability:       vector.AvailabilityHigh,       // 高可用性影响
	}

	// 创建计算器并计算评分
	calculator := cvss.NewCalculator(cvss3x)
	score, _ := calculator.Calculate()
	severity := calculator.GetSeverityRating(score)

	// 获取向量字符串
	vectorStr := cvss3x.String()
	fmt.Printf("手动构建的CVSS向量: %s\n", vectorStr)
	fmt.Printf("评分: %.1f, 严重性: %s\n", score, severity)

	// 转换为JSON
	jsonData, _ := cvss3x.ToJSON(calculator)
	fmt.Println("JSON输出:")

	var prettyJSON map[string]interface{}
	json.Unmarshal(jsonData, &prettyJSON)
	prettyJSONBytes, _ := json.MarshalIndent(prettyJSON, "", "  ")
	fmt.Println(string(prettyJSONBytes))
}
