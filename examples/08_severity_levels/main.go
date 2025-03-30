package main

import (
	"fmt"
	"log"

	"github.com/scagogogo/cvss-parser/pkg/cvss"
	"github.com/scagogogo/cvss-parser/pkg/parser"
)

func main() {
	// =====================================================
	// CVSS严重级别示例
	// 展示如何处理和解释CVSS的严重性等级
	// =====================================================

	fmt.Println("CVSS严重级别示例")
	fmt.Println("=====================================================")

	// 1. 不同严重性级别的示例向量
	fmt.Println("\n1. 不同严重性级别的示例向量")

	// 定义不同严重性级别的示例向量
	severityVectors := []struct {
		name     string
		vector   string
		expected string
	}{
		{
			name:     "关键(Critical)",
			vector:   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
			expected: "Critical",
		},
		{
			name:     "高(High)",
			vector:   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
			expected: "High",
		},
		{
			name:     "中(Medium)",
			vector:   "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N",
			expected: "Medium",
		},
		{
			name:     "低(Low)",
			vector:   "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N",
			expected: "Low",
		},
		{
			name:     "无(None)",
			vector:   "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N",
			expected: "None",
		},
	}

	// 解析并显示每个向量的严重性级别
	for _, sv := range severityVectors {
		p := parser.NewCvss3xParser(sv.vector)
		cvss3x, err := p.Parse()
		if err != nil {
			log.Printf("解析失败: %v\n", err)
			continue
		}

		calculator := cvss.NewCalculator(cvss3x)
		score, err := calculator.Calculate()
		if err != nil {
			log.Printf("计算评分失败: %v\n", err)
			continue
		}

		severity := calculator.GetSeverityRating(score)

		// 显示结果
		fmt.Printf("   %s:\n", sv.name)
		fmt.Printf("   - 向量: %s\n", sv.vector)
		fmt.Printf("   - 评分: %.1f\n", score)
		fmt.Printf("   - 严重级别: %s\n", severity)
		fmt.Printf("   - 匹配预期: %v\n\n", severity == sv.expected)
	}

	// 2. 严重性级别边界值测试
	fmt.Println("\n2. 严重性级别边界值测试")

	// 定义边界值测试向量
	boundaryVectors := []struct {
		name   string
		score  float64
		lower  string
		higher string
	}{
		{
			name:   "无/低边界(0.1/0.0)",
			score:  0.1,
			lower:  "None",
			higher: "Low",
		},
		{
			name:   "低/中边界(4.0/3.9)",
			score:  4.0,
			lower:  "Low",
			higher: "Medium",
		},
		{
			name:   "中/高边界(7.0/6.9)",
			score:  7.0,
			lower:  "Medium",
			higher: "High",
		},
		{
			name:   "高/关键边界(9.0/8.9)",
			score:  9.0,
			lower:  "High",
			higher: "Critical",
		},
	}

	// 演示边界值的严重性级别
	calculator := cvss.NewCalculator(nil) // 仅用于调用GetSeverityRating方法

	for _, bv := range boundaryVectors {
		lowerBoundary := bv.score - 0.1
		higherBoundary := bv.score

		lowerSeverity := calculator.GetSeverityRating(lowerBoundary)
		higherSeverity := calculator.GetSeverityRating(higherBoundary)

		fmt.Printf("   %s:\n", bv.name)
		fmt.Printf("   - 较低分数: %.1f -> 严重级别: %s\n", lowerBoundary, lowerSeverity)
		fmt.Printf("   - 较高分数: %.1f -> 严重级别: %s\n", higherBoundary, higherSeverity)
		fmt.Printf("   - 匹配预期: %v/%v\n\n",
			lowerSeverity == bv.lower,
			higherSeverity == bv.higher)
	}

	// 3. 严重性级别的实际应用
	fmt.Println("\n3. 严重性级别的实际应用")

	// 演示如何使用严重性级别进行漏洞优先级排序
	fmt.Println("   3.1 漏洞优先级排序:")
	fmt.Println("   根据严重性级别和评分对漏洞进行优先级排序:")
	fmt.Println("   - Critical (9.0-10.0): 立即修复，通常需要在24-48小时内处理")
	fmt.Println("   - High (7.0-8.9): 尽快修复，通常需要在一周内处理")
	fmt.Println("   - Medium (4.0-6.9): 计划修复，通常在下一个发布周期内处理")
	fmt.Println("   - Low (0.1-3.9): 可选修复，根据业务需求决定是否修复")
	fmt.Println("   - None (0.0): 无需修复")

	// 创建一个包含多个漏洞的列表
	vulnerabilities := []struct {
		id       string
		name     string
		vector   string
		priority int // 自定义优先级，用于排序
	}{
		{
			id:       "CVE-2023-0001",
			name:     "远程代码执行漏洞",
			vector:   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
			priority: 1,
		},
		{
			id:       "CVE-2023-0002",
			name:     "本地权限提升漏洞",
			vector:   "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
			priority: 2,
		},
		{
			id:       "CVE-2023-0003",
			name:     "信息泄露漏洞",
			vector:   "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
			priority: 3,
		},
		{
			id:       "CVE-2023-0004",
			name:     "拒绝服务漏洞",
			vector:   "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H",
			priority: 4,
		},
		{
			id:       "CVE-2023-0005",
			name:     "跨站脚本漏洞",
			vector:   "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
			priority: 5,
		},
	}

	// 解析并显示每个漏洞的严重性级别和推荐修复时间
	fmt.Println("\n   漏洞列表和修复建议:")
	for _, vuln := range vulnerabilities {
		p := parser.NewCvss3xParser(vuln.vector)
		cvss3x, _ := p.Parse()
		calculator := cvss.NewCalculator(cvss3x)
		score, _ := calculator.Calculate()
		severity := calculator.GetSeverityRating(score)

		// 确定建议的修复时间
		var remediation string
		switch severity {
		case "Critical":
			remediation = "24-48小时内"
		case "High":
			remediation = "一周内"
		case "Medium":
			remediation = "下一个发布周期"
		case "Low":
			remediation = "按业务需求"
		default:
			remediation = "无需修复"
		}

		fmt.Printf("   %s - %s (P%d):\n", vuln.id, vuln.name, vuln.priority)
		fmt.Printf("   - 向量: %s\n", vuln.vector)
		fmt.Printf("   - 评分: %.1f (%s)\n", score, severity)
		fmt.Printf("   - 建议修复时间: %s\n\n", remediation)
	}

	// 4. 自定义严重性级别映射
	fmt.Println("\n4. 自定义严重性级别映射")
	fmt.Println("   有时组织可能使用自定义的严重性级别映射，而不是标准的CVSS严重性级别")

	// 定义自定义严重性级别映射函数
	customSeverityRating := func(score float64) string {
		switch {
		case score >= 9.5:
			return "紧急(Urgent)"
		case score >= 8.0:
			return "严重(Severe)"
		case score >= 5.0:
			return "重要(Important)"
		case score >= 2.0:
			return "中等(Moderate)"
		case score > 0.0:
			return "次要(Minor)"
		default:
			return "无风险(No Risk)"
		}
	}

	// 测试自定义严重性级别映射
	testScores := []float64{10.0, 9.3, 8.7, 7.5, 6.2, 4.8, 3.5, 1.2, 0.0}

	fmt.Println("   标准CVSS严重性级别与自定义严重性级别比较:")
	for _, score := range testScores {
		standardSeverity := calculator.GetSeverityRating(score)
		customSeverity := customSeverityRating(score)

		fmt.Printf("   - 评分: %.1f\n", score)
		fmt.Printf("     标准级别: %s\n", standardSeverity)
		fmt.Printf("     自定义级别: %s\n\n", customSeverity)
	}

	// 5. 时间与环境因素对严重性级别的影响
	fmt.Println("\n5. 时间与环境因素对严重性级别的影响")

	// 基础向量
	baseVector := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	fmt.Printf("   基础向量: %s\n", baseVector)

	// 解析基础向量
	p := parser.NewCvss3xParser(baseVector)
	baseCvss, _ := p.Parse()
	baseCalculator := cvss.NewCalculator(baseCvss)
	baseScore, _ := baseCalculator.Calculate()
	baseSeverity := baseCalculator.GetSeverityRating(baseScore)

	fmt.Printf("   基础评分: %.1f (%s)\n\n", baseScore, baseSeverity)

	// 添加时间因素
	temporalVector := baseVector + "/E:P/RL:T/RC:R"
	fmt.Printf("   带时间因素的向量: %s\n", temporalVector)

	// 解析时间向量
	p = parser.NewCvss3xParser(temporalVector)
	temporalCvss, _ := p.Parse()
	temporalCalculator := cvss.NewCalculator(temporalCvss)
	temporalScore, _ := temporalCalculator.Calculate()
	temporalSeverity := temporalCalculator.GetSeverityRating(temporalScore)

	fmt.Printf("   时间评分: %.1f (%s)\n", temporalScore, temporalSeverity)
	fmt.Printf("   评分变化: %.1f\n\n", temporalScore-baseScore)

	// 添加环境因素
	environmentalVector := temporalVector + "/CR:H/IR:M/AR:L/MAV:A/MAC:H"
	fmt.Printf("   带环境因素的向量: %s\n", environmentalVector)

	// 解析环境向量
	p = parser.NewCvss3xParser(environmentalVector)
	environmentalCvss, _ := p.Parse()
	environmentalCalculator := cvss.NewCalculator(environmentalCvss)
	environmentalScore, _ := environmentalCalculator.Calculate()
	environmentalSeverity := environmentalCalculator.GetSeverityRating(environmentalScore)

	fmt.Printf("   环境评分: %.1f (%s)\n", environmentalScore, environmentalSeverity)
	fmt.Printf("   评分变化: %.1f (相对于基础评分)\n", environmentalScore-baseScore)
	fmt.Printf("   评分变化: %.1f (相对于时间评分)\n", environmentalScore-temporalScore)

	// 级别变化总结
	fmt.Println("\n   严重性级别变化总结:")
	fmt.Printf("   - 基础级别: %s (%.1f)\n", baseSeverity, baseScore)
	fmt.Printf("   - 时间级别: %s (%.1f)\n", temporalSeverity, temporalScore)
	fmt.Printf("   - 环境级别: %s (%.1f)\n", environmentalSeverity, environmentalScore)

	if baseSeverity != environmentalSeverity {
		fmt.Printf("   在考虑时间和环境因素后，严重性级别从 %s 变为 %s\n",
			baseSeverity, environmentalSeverity)
	} else {
		fmt.Println("   尽管评分有所变化，但严重性级别保持不变")
	}

	fmt.Println("\n=====================================================")
	fmt.Println("CVSS严重级别示例结束")
}
