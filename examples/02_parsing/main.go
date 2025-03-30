package main

import (
	"fmt"
	"log"

	"github.com/scagogogo/cvss-parser/pkg/cvss"
	"github.com/scagogogo/cvss-parser/pkg/parser"
)

func main() {
	// =====================================================
	// CVSS向量解析示例
	// 展示如何解析不同类型和严重级别的CVSS向量
	// =====================================================

	// 定义多个不同类型和严重级别的CVSS向量
	vectors := []struct {
		description string
		vector      string
		expected    string // 期望的严重级别
	}{
		{
			description: "关键级别(Critical) - 网络攻击，低复杂度，无权限要求，高影响",
			vector:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			expected:    "Critical",
		},
		{
			description: "高级别(High) - 本地攻击，低复杂度，低权限要求",
			vector:      "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
			expected:    "High",
		},
		{
			description: "中级别(Medium) - 网络攻击，高复杂度，需要用户交互",
			vector:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:L",
			expected:    "Medium",
		},
		{
			description: "低级别(Low) - 物理攻击，高复杂度，高权限要求",
			vector:      "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:N",
			expected:    "Low",
		},
		{
			description: "最高级别(Critical) - 网络攻击，改变范围",
			vector:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
			expected:    "Critical",
		},
		{
			description: "CVSS 3.0版本 - 向后兼容",
			vector:      "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:L",
			expected:    "Medium",
		},
	}

	fmt.Println("CVSS向量解析示例")
	fmt.Println("=====================================================")

	// 遍历并解析每个向量
	for i, v := range vectors {
		fmt.Printf("\n%d. %s\n", i+1, v.description)
		fmt.Printf("   向量: %s\n", v.vector)

		// 创建解析器并解析向量
		p := parser.NewCvss3xParser(v.vector)
		cvss3x, err := p.Parse()
		if err != nil {
			log.Printf("   解析失败: %v\n", err)
			continue
		}

		// 获取版本信息
		fmt.Printf("   CVSS版本: %d.%d\n", cvss3x.MajorVersion, cvss3x.MinorVersion)

		// 创建计算器并计算评分
		calculator := cvss.NewCalculator(cvss3x)
		score, err := calculator.Calculate()
		if err != nil {
			log.Printf("   计算失败: %v\n", err)
			continue
		}

		// 获取严重性等级并与期望值比较
		severity := calculator.GetSeverityRating(score)
		fmt.Printf("   评分: %.1f, 严重性: %s", score, severity)

		// 检查是否与期望严重性匹配
		if severity == v.expected {
			fmt.Printf(" ✓")
		} else {
			fmt.Printf(" ✗ (期望: %s)", v.expected)
		}
		fmt.Println()

		// 还原向量字符串并比较
		restored := cvss3x.String()
		fmt.Printf("   重构向量: %s\n", restored)

		// 打印一些主要指标值
		printMainMetrics(cvss3x)
	}

	fmt.Println("\n=====================================================")
	fmt.Println("CVSS向量解析示例结束")
}

// 打印向量的主要指标值
func printMainMetrics(cvss3x *cvss.Cvss3x) {
	if cvss3x.Cvss3xBase == nil {
		return
	}

	// 提取基础向量得分
	avScore := "无"
	if cvss3x.Cvss3xBase.AttackVector != nil {
		avScore = fmt.Sprintf("%.2f", cvss3x.Cvss3xBase.AttackVector.GetScore())
	}

	acScore := "无"
	if cvss3x.Cvss3xBase.AttackComplexity != nil {
		acScore = fmt.Sprintf("%.2f", cvss3x.Cvss3xBase.AttackComplexity.GetScore())
	}

	prScore := "无"
	if cvss3x.Cvss3xBase.PrivilegesRequired != nil {
		prScore = fmt.Sprintf("%.2f", cvss3x.Cvss3xBase.PrivilegesRequired.GetScore())
	}

	// 打印基础得分情况
	fmt.Printf("   主要指标得分: AV=%s, AC=%s, PR=%s\n", avScore, acScore, prScore)
}
