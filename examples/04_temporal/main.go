package main

import (
	"fmt"
	"log"

	"github.com/scagogogo/cvss-parser/pkg/cvss"
	"github.com/scagogogo/cvss-parser/pkg/parser"
	"github.com/scagogogo/cvss-parser/pkg/vector"
)

func main() {
	// =====================================================
	// CVSS时间指标(Temporal Metrics)示例
	// 展示如何使用时间指标及其对评分的影响
	// =====================================================

	fmt.Println("CVSS时间指标(Temporal Metrics)示例")
	fmt.Println("=====================================================")

	// 基础向量 - 没有时间指标
	baseVector := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	fmt.Println("1. 基础向量(无时间指标):")
	fmt.Printf("   %s\n", baseVector)
	calculateScore(baseVector)

	// 添加时间指标 - 漏洞利用成熟度
	fmt.Println("\n2. 添加时间指标 - 漏洞利用成熟度(E)对评分的影响:")
	eValues := []struct {
		code  string
		name  string
		value rune
	}{
		{"E:X", "未定义(Not Defined)", 'X'},
		{"E:U", "未证实(Unproven)", 'U'},
		{"E:P", "概念验证(Proof-of-Concept)", 'P'},
		{"E:F", "功能性(Functional)", 'F'},
		{"E:H", "高度(High)", 'H'},
	}

	for _, e := range eValues {
		temporalVector := fmt.Sprintf("%s/%s", baseVector, e.code)
		fmt.Printf("   %s - %s\n", e.code, e.name)
		fmt.Printf("   向量: %s\n", temporalVector)
		calculateScore(temporalVector)
		fmt.Println()
	}

	// 添加时间指标 - 修复级别
	fmt.Println("\n3. 添加时间指标 - 修复级别(RL)对评分的影响:")
	rlValues := []struct {
		code  string
		name  string
		value rune
	}{
		{"RL:X", "未定义(Not Defined)", 'X'},
		{"RL:O", "官方修复(Official Fix)", 'O'},
		{"RL:T", "临时修复(Temporary Fix)", 'T'},
		{"RL:W", "解决方法(Workaround)", 'W'},
		{"RL:U", "不可用(Unavailable)", 'U'},
	}

	for _, rl := range rlValues {
		temporalVector := fmt.Sprintf("%s/%s", baseVector, rl.code)
		fmt.Printf("   %s - %s\n", rl.code, rl.name)
		fmt.Printf("   向量: %s\n", temporalVector)
		calculateScore(temporalVector)
		fmt.Println()
	}

	// 添加时间指标 - 报告可信度
	fmt.Println("\n4. 添加时间指标 - 报告可信度(RC)对评分的影响:")
	rcValues := []struct {
		code  string
		name  string
		value rune
	}{
		{"RC:X", "未定义(Not Defined)", 'X'},
		{"RC:U", "未知(Unknown)", 'U'},
		{"RC:R", "合理(Reasonable)", 'R'},
		{"RC:C", "已确认(Confirmed)", 'C'},
	}

	for _, rc := range rcValues {
		temporalVector := fmt.Sprintf("%s/%s", baseVector, rc.code)
		fmt.Printf("   %s - %s\n", rc.code, rc.name)
		fmt.Printf("   向量: %s\n", temporalVector)
		calculateScore(temporalVector)
		fmt.Println()
	}

	// 综合时间指标
	fmt.Println("\n5. 综合时间指标对评分的影响:")

	// 最坏情况
	worstCase := fmt.Sprintf("%s/E:H/RL:U/RC:C", baseVector)
	fmt.Printf("   最坏情况: %s\n", worstCase)
	fmt.Printf("   (高度利用、无修复方案、已确认)\n")
	calculateScore(worstCase)

	// 中等情况
	mediumCase := fmt.Sprintf("%s/E:F/RL:W/RC:R", baseVector)
	fmt.Printf("\n   中等情况: %s\n", mediumCase)
	fmt.Printf("   (功能性利用、有解决方法、合理可信)\n")
	calculateScore(mediumCase)

	// 最好情况
	bestCase := fmt.Sprintf("%s/E:U/RL:O/RC:U", baseVector)
	fmt.Printf("\n   最好情况: %s\n", bestCase)
	fmt.Printf("   (未证实利用、官方修复、未知可信度)\n")
	calculateScore(bestCase)

	// 手动构建带时间指标的CVSS向量
	fmt.Println("\n6. 手动构建带时间指标的CVSS向量:")
	demonstrateManualTemporal()

	fmt.Println("\n=====================================================")
	fmt.Println("CVSS时间指标示例结束")
}

// 计算并显示CVSS评分
func calculateScore(vectorStr string) {
	// 解析向量
	p := parser.NewCvss3xParser(vectorStr)
	cvss3x, err := p.Parse()
	if err != nil {
		log.Printf("解析失败: %v\n", err)
		return
	}

	// 创建计算器并计算评分
	calculator := cvss.NewCalculator(cvss3x)
	score, err := calculator.Calculate()
	if err != nil {
		log.Printf("计算评分失败: %v\n", err)
		return
	}

	// 获取严重性等级
	severity := calculator.GetSeverityRating(score)

	// 判断是否有时间指标
	hasTemporal := false
	if cvss3x.Cvss3xTemporal != nil {
		if cvss3x.Cvss3xTemporal.ExploitCodeMaturity != nil ||
			cvss3x.Cvss3xTemporal.RemediationLevel != nil ||
			cvss3x.Cvss3xTemporal.ReportConfidence != nil {
			hasTemporal = true
		}
	}

	// 计算并展示基础评分与时间评分的差异
	if hasTemporal {
		// 创建一个只有基础指标的副本，以便比较
		baseOnly := &cvss.Cvss3x{
			MajorVersion: cvss3x.MajorVersion,
			MinorVersion: cvss3x.MinorVersion,
			Cvss3xBase:   cvss3x.Cvss3xBase,
		}

		// 计算基础评分
		baseCalculator := cvss.NewCalculator(baseOnly)
		baseScore, _ := baseCalculator.Calculate()
		baseSeverity := baseCalculator.GetSeverityRating(baseScore)

		// 显示评分差异
		fmt.Printf("   基础评分: %.1f (%s)\n", baseScore, baseSeverity)
		fmt.Printf("   时间评分: %.1f (%s)\n", score, severity)
		fmt.Printf("   评分变化: %.1f\n", score-baseScore)
	} else {
		fmt.Printf("   基础评分: %.1f (%s)\n", score, severity)
	}
}

// 演示如何手动构建带时间指标的CVSS向量
func demonstrateManualTemporal() {
	// 创建一个新的CVSS 3.1对象
	cvss3x := cvss.NewCvss3x()
	cvss3x.MajorVersion = 3
	cvss3x.MinorVersion = 1

	// 填充基础指标
	cvss3x.Cvss3xBase = &cvss.Cvss3xBase{
		AttackVector:       vector.AttackVectorNetwork,
		AttackComplexity:   vector.AttackComplexityLow,
		PrivilegesRequired: vector.PrivilegesRequiredNone,
		UserInteraction:    vector.UserInteractionNone,
		Scope:              vector.ScopeUnchanged,
		Confidentiality:    vector.ConfidentialityHigh,
		Integrity:          vector.IntegrityHigh,
		Availability:       vector.AvailabilityHigh,
	}

	// 填充时间指标
	cvss3x.Cvss3xTemporal = &cvss.Cvss3xTemporal{
		ExploitCodeMaturity: vector.ExploitCodeMaturityFunctional, // 功能性利用代码
		RemediationLevel:    vector.RemediationLevelOfficialFix,   // 官方修复
		ReportConfidence:    vector.ReportConfidenceConfirmed,     // 已确认
	}

	// 获取向量字符串
	vectorStr := cvss3x.String()

	// 创建计算器并计算评分
	calculator := cvss.NewCalculator(cvss3x)
	temporalScore, _ := calculator.Calculate()
	temporalSeverity := calculator.GetSeverityRating(temporalScore)

	// 仅使用基础指标计算评分以进行比较
	baseOnly := &cvss.Cvss3x{
		MajorVersion: cvss3x.MajorVersion,
		MinorVersion: cvss3x.MinorVersion,
		Cvss3xBase:   cvss3x.Cvss3xBase,
	}
	baseCalculator := cvss.NewCalculator(baseOnly)
	baseScore, _ := baseCalculator.Calculate()
	baseSeverity := baseCalculator.GetSeverityRating(baseScore)

	// 显示结果
	fmt.Printf("   手动构建的向量: %s\n", vectorStr)
	fmt.Printf("   基础评分: %.1f (%s)\n", baseScore, baseSeverity)
	fmt.Printf("   时间评分: %.1f (%s)\n", temporalScore, temporalSeverity)
	fmt.Printf("   评分变化: %.1f\n", temporalScore-baseScore)

	// 展示不同时间指标的影响
	fmt.Println("\n   时间指标的值及其对评分的影响:")
	fmt.Printf("   - 漏洞利用成熟度(E): %s (%.2f)\n",
		cvss3x.Cvss3xTemporal.ExploitCodeMaturity.GetLongValue(),
		cvss3x.Cvss3xTemporal.ExploitCodeMaturity.GetScore())
	fmt.Printf("   - 修复级别(RL): %s (%.2f)\n",
		cvss3x.Cvss3xTemporal.RemediationLevel.GetLongValue(),
		cvss3x.Cvss3xTemporal.RemediationLevel.GetScore())
	fmt.Printf("   - 报告可信度(RC): %s (%.2f)\n",
		cvss3x.Cvss3xTemporal.ReportConfidence.GetLongValue(),
		cvss3x.Cvss3xTemporal.ReportConfidence.GetScore())
}
