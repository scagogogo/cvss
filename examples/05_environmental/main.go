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
	// CVSS环境指标(Environmental Metrics)示例
	// 展示如何使用环境指标及其对评分的影响
	// =====================================================

	fmt.Println("CVSS环境指标(Environmental Metrics)示例")
	fmt.Println("=====================================================")

	// 基础向量 - 没有环境指标
	baseVector := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	fmt.Println("1. 基础向量(无环境指标):")
	fmt.Printf("   %s\n", baseVector)
	calculateScoreWithEnvironmental(baseVector)

	// CIA需求指标
	fmt.Println("\n2. CIA需求(Requirements)指标对评分的影响:")

	// 机密性需求(CR)
	fmt.Println("\n   2.1 机密性需求(CR)对评分的影响:")
	crValues := []struct {
		code string
		name string
	}{
		{"CR:X", "未定义(Not Defined)"},
		{"CR:L", "低(Low)"},
		{"CR:M", "中(Medium)"},
		{"CR:H", "高(High)"},
	}

	for _, cr := range crValues {
		envVector := fmt.Sprintf("%s/%s", baseVector, cr.code)
		fmt.Printf("   %s - %s\n", cr.code, cr.name)
		fmt.Printf("   向量: %s\n", envVector)
		calculateScoreWithEnvironmental(envVector)
		fmt.Println()
	}

	// 完整性需求(IR)
	fmt.Println("\n   2.2 完整性需求(IR)对评分的影响:")
	irValues := []struct {
		code string
		name string
	}{
		{"IR:X", "未定义(Not Defined)"},
		{"IR:L", "低(Low)"},
		{"IR:M", "中(Medium)"},
		{"IR:H", "高(High)"},
	}

	for _, ir := range irValues {
		envVector := fmt.Sprintf("%s/%s", baseVector, ir.code)
		fmt.Printf("   %s - %s\n", ir.code, ir.name)
		fmt.Printf("   向量: %s\n", envVector)
		calculateScoreWithEnvironmental(envVector)
		fmt.Println()
	}

	// 可用性需求(AR)
	fmt.Println("\n   2.3 可用性需求(AR)对评分的影响:")
	arValues := []struct {
		code string
		name string
	}{
		{"AR:X", "未定义(Not Defined)"},
		{"AR:L", "低(Low)"},
		{"AR:M", "中(Medium)"},
		{"AR:H", "高(High)"},
	}

	for _, ar := range arValues {
		envVector := fmt.Sprintf("%s/%s", baseVector, ar.code)
		fmt.Printf("   %s - %s\n", ar.code, ar.name)
		fmt.Printf("   向量: %s\n", envVector)
		calculateScoreWithEnvironmental(envVector)
		fmt.Println()
	}

	// 修改攻击指标
	fmt.Println("\n3. 修改攻击指标对评分的影响:")

	// 修改攻击向量(MAV)
	fmt.Println("\n   3.1 修改攻击向量(MAV)对评分的影响:")
	mavValues := []struct {
		code string
		name string
	}{
		{"MAV:X", "未定义(Not Defined)"},
		{"MAV:N", "网络(Network)"},
		{"MAV:A", "相邻(Adjacent)"},
		{"MAV:L", "本地(Local)"},
		{"MAV:P", "物理(Physical)"},
	}

	for _, mav := range mavValues {
		envVector := fmt.Sprintf("%s/%s", baseVector, mav.code)
		fmt.Printf("   %s - %s\n", mav.code, mav.name)
		fmt.Printf("   向量: %s\n", envVector)
		calculateScoreWithEnvironmental(envVector)
		fmt.Println()
	}

	// 修改攻击复杂性(MAC)
	fmt.Println("\n   3.2 修改攻击复杂性(MAC)对评分的影响:")
	macValues := []struct {
		code string
		name string
	}{
		{"MAC:X", "未定义(Not Defined)"},
		{"MAC:L", "低(Low)"},
		{"MAC:H", "高(High)"},
	}

	for _, mac := range macValues {
		envVector := fmt.Sprintf("%s/%s", baseVector, mac.code)
		fmt.Printf("   %s - %s\n", mac.code, mac.name)
		fmt.Printf("   向量: %s\n", envVector)
		calculateScoreWithEnvironmental(envVector)
		fmt.Println()
	}

	// 组合修改指标
	fmt.Println("\n4. 组合环境指标示例:")

	// 提高安全性组合
	betterSecurityVector := fmt.Sprintf("%s/CR:L/IR:L/AR:L/MAV:P/MAC:H/MPR:H/MUI:R", baseVector)
	fmt.Printf("   4.1 提高安全性组合:\n")
	fmt.Printf("   向量: %s\n", betterSecurityVector)
	fmt.Printf("   (降低CIA需求、更难的攻击条件)\n")
	calculateScoreWithEnvironmental(betterSecurityVector)

	// 降低安全性组合
	worseSecurityVector := fmt.Sprintf("%s/CR:H/IR:H/AR:H/MAV:N/MAC:L/MPR:N/MUI:N", baseVector)
	fmt.Printf("\n   4.2 降低安全性组合:\n")
	fmt.Printf("   向量: %s\n", worseSecurityVector)
	fmt.Printf("   (提高CIA需求、更容易的攻击条件)\n")
	calculateScoreWithEnvironmental(worseSecurityVector)

	// 综合示例（带时间指标和环境指标）
	fmt.Println("\n5. 综合示例（同时使用时间指标和环境指标）:")
	completeVector := fmt.Sprintf("%s/E:F/RL:O/RC:C/CR:H/IR:M/AR:L/MAV:A/MAC:H", baseVector)
	fmt.Printf("   向量: %s\n", completeVector)
	calculateScoreWithEnvironmental(completeVector)

	// 手动构建带环境指标的CVSS向量
	fmt.Println("\n6. 手动构建带环境指标的CVSS向量:")
	demonstrateManualEnvironmental()

	fmt.Println("\n=====================================================")
	fmt.Println("CVSS环境指标示例结束")
}

// 计算并显示带环境指标的CVSS评分
func calculateScoreWithEnvironmental(vectorStr string) {
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

	// 判断是否有环境指标
	hasEnvironmental := false
	if cvss3x.Cvss3xEnvironmental != nil {
		// 检查是否有任何环境指标
		if cvss3x.Cvss3xEnvironmental.ConfidentialityRequirement != nil ||
			cvss3x.Cvss3xEnvironmental.IntegrityRequirement != nil ||
			cvss3x.Cvss3xEnvironmental.AvailabilityRequirement != nil ||
			cvss3x.Cvss3xEnvironmental.ModifiedAttackVector != nil ||
			cvss3x.Cvss3xEnvironmental.ModifiedAttackComplexity != nil ||
			cvss3x.Cvss3xEnvironmental.ModifiedPrivilegesRequired != nil ||
			cvss3x.Cvss3xEnvironmental.ModifiedUserInteraction != nil ||
			cvss3x.Cvss3xEnvironmental.ModifiedScope != nil ||
			cvss3x.Cvss3xEnvironmental.ModifiedConfidentiality != nil ||
			cvss3x.Cvss3xEnvironmental.ModifiedIntegrity != nil ||
			cvss3x.Cvss3xEnvironmental.ModifiedAvailability != nil {
			hasEnvironmental = true
		}
	}

	// 计算并展示基础评分与环境评分的差异
	if hasEnvironmental {
		// 创建一个只有基础指标的副本，以便比较
		baseOnly := &cvss.Cvss3x{
			MajorVersion:   cvss3x.MajorVersion,
			MinorVersion:   cvss3x.MinorVersion,
			Cvss3xBase:     cvss3x.Cvss3xBase,
			Cvss3xTemporal: cvss3x.Cvss3xTemporal, // 保留时间指标，如果有的话
		}

		// 计算基础评分
		baseCalculator := cvss.NewCalculator(baseOnly)
		baseScore, _ := baseCalculator.Calculate()
		baseSeverity := baseCalculator.GetSeverityRating(baseScore)

		// 显示评分差异
		fmt.Printf("   基础/时间评分: %.1f (%s)\n", baseScore, baseSeverity)
		fmt.Printf("   环境评分: %.1f (%s)\n", score, severity)
		fmt.Printf("   评分变化: %.1f\n", score-baseScore)

		// 显示哪些环境指标被修改了
		printEnvironmentalModifiers(cvss3x)
	} else {
		fmt.Printf("   基础评分: %.1f (%s)\n", score, severity)
	}
}

// 打印环境指标修改信息
func printEnvironmentalModifiers(cvss3x *cvss.Cvss3x) {
	if cvss3x.Cvss3xEnvironmental == nil {
		return
	}

	fmt.Println("   环境指标修改:")

	// 检查CIA需求
	if cvss3x.Cvss3xEnvironmental.ConfidentialityRequirement != nil {
		fmt.Printf("   - 机密性需求(CR): %s\n",
			cvss3x.Cvss3xEnvironmental.ConfidentialityRequirement.GetLongValue())
	}

	if cvss3x.Cvss3xEnvironmental.IntegrityRequirement != nil {
		fmt.Printf("   - 完整性需求(IR): %s\n",
			cvss3x.Cvss3xEnvironmental.IntegrityRequirement.GetLongValue())
	}

	if cvss3x.Cvss3xEnvironmental.AvailabilityRequirement != nil {
		fmt.Printf("   - 可用性需求(AR): %s\n",
			cvss3x.Cvss3xEnvironmental.AvailabilityRequirement.GetLongValue())
	}

	// 检查修改的攻击指标
	if cvss3x.Cvss3xEnvironmental.ModifiedAttackVector != nil {
		fmt.Printf("   - 修改攻击向量(MAV): %s\n",
			cvss3x.Cvss3xEnvironmental.ModifiedAttackVector.GetLongValue())
	}

	if cvss3x.Cvss3xEnvironmental.ModifiedAttackComplexity != nil {
		fmt.Printf("   - 修改攻击复杂性(MAC): %s\n",
			cvss3x.Cvss3xEnvironmental.ModifiedAttackComplexity.GetLongValue())
	}

	if cvss3x.Cvss3xEnvironmental.ModifiedPrivilegesRequired != nil {
		fmt.Printf("   - 修改权限要求(MPR): %s\n",
			cvss3x.Cvss3xEnvironmental.ModifiedPrivilegesRequired.GetLongValue())
	}

	if cvss3x.Cvss3xEnvironmental.ModifiedUserInteraction != nil {
		fmt.Printf("   - 修改用户交互(MUI): %s\n",
			cvss3x.Cvss3xEnvironmental.ModifiedUserInteraction.GetLongValue())
	}

	if cvss3x.Cvss3xEnvironmental.ModifiedScope != nil {
		fmt.Printf("   - 修改范围(MS): %s\n",
			cvss3x.Cvss3xEnvironmental.ModifiedScope.GetLongValue())
	}

	if cvss3x.Cvss3xEnvironmental.ModifiedConfidentiality != nil {
		fmt.Printf("   - 修改机密性(MC): %s\n",
			cvss3x.Cvss3xEnvironmental.ModifiedConfidentiality.GetLongValue())
	}

	if cvss3x.Cvss3xEnvironmental.ModifiedIntegrity != nil {
		fmt.Printf("   - 修改完整性(MI): %s\n",
			cvss3x.Cvss3xEnvironmental.ModifiedIntegrity.GetLongValue())
	}

	if cvss3x.Cvss3xEnvironmental.ModifiedAvailability != nil {
		fmt.Printf("   - 修改可用性(MA): %s\n",
			cvss3x.Cvss3xEnvironmental.ModifiedAvailability.GetLongValue())
	}
}

// 演示如何手动构建带环境指标的CVSS向量
func demonstrateManualEnvironmental() {
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

	// 填充环境指标
	cvss3x.Cvss3xEnvironmental = &cvss.Cvss3xEnvironmental{
		// CIA需求
		ConfidentialityRequirement: vector.ConfidentialityRequirementHigh,
		IntegrityRequirement:       vector.IntegrityRequirementMedium,
		AvailabilityRequirement:    vector.AvailabilityRequirementLow,

		// 修改攻击指标
		ModifiedAttackVector:       vector.ModifiedAttackVectorAdjacent,
		ModifiedAttackComplexity:   vector.ModifiedAttackComplexityHigh,
		ModifiedPrivilegesRequired: vector.ModifiedPrivilegesRequiredLow,
		ModifiedUserInteraction:    vector.ModifiedUserInteractionRequired,

		// 修改影响指标
		ModifiedScope:           vector.ModifiedScopeChanged,
		ModifiedConfidentiality: vector.ModifiedConfidentialityLow,
		ModifiedIntegrity:       vector.ModifiedIntegrityLow,
		ModifiedAvailability:    vector.ModifiedAvailabilityLow,
	}

	// 获取向量字符串
	vectorStr := cvss3x.String()

	// 创建计算器并计算评分
	calculator := cvss.NewCalculator(cvss3x)
	envScore, _ := calculator.Calculate()
	envSeverity := calculator.GetSeverityRating(envScore)

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
	fmt.Printf("   环境评分: %.1f (%s)\n", envScore, envSeverity)
	fmt.Printf("   评分变化: %.1f\n", envScore-baseScore)

	// 详细显示环境指标
	fmt.Println("\n   环境指标详情:")

	// CIA需求
	fmt.Printf("   1. CIA需求指标:\n")
	fmt.Printf("      - 机密性需求(CR): %s (%.2f)\n",
		cvss3x.Cvss3xEnvironmental.ConfidentialityRequirement.GetLongValue(),
		cvss3x.Cvss3xEnvironmental.ConfidentialityRequirement.GetScore())
	fmt.Printf("      - 完整性需求(IR): %s (%.2f)\n",
		cvss3x.Cvss3xEnvironmental.IntegrityRequirement.GetLongValue(),
		cvss3x.Cvss3xEnvironmental.IntegrityRequirement.GetScore())
	fmt.Printf("      - 可用性需求(AR): %s (%.2f)\n",
		cvss3x.Cvss3xEnvironmental.AvailabilityRequirement.GetLongValue(),
		cvss3x.Cvss3xEnvironmental.AvailabilityRequirement.GetScore())

	// 修改攻击指标
	fmt.Printf("\n   2. 修改攻击指标:\n")
	fmt.Printf("      - 修改攻击向量(MAV): %s (%.2f)\n",
		cvss3x.Cvss3xEnvironmental.ModifiedAttackVector.GetLongValue(),
		cvss3x.Cvss3xEnvironmental.ModifiedAttackVector.GetScore())
	fmt.Printf("      - 修改攻击复杂性(MAC): %s (%.2f)\n",
		cvss3x.Cvss3xEnvironmental.ModifiedAttackComplexity.GetLongValue(),
		cvss3x.Cvss3xEnvironmental.ModifiedAttackComplexity.GetScore())

	// 修改影响指标
	fmt.Printf("\n   3. 修改影响指标:\n")
	fmt.Printf("      - 修改机密性(MC): %s (%.2f)\n",
		cvss3x.Cvss3xEnvironmental.ModifiedConfidentiality.GetLongValue(),
		cvss3x.Cvss3xEnvironmental.ModifiedConfidentiality.GetScore())
	fmt.Printf("      - 修改完整性(MI): %s (%.2f)\n",
		cvss3x.Cvss3xEnvironmental.ModifiedIntegrity.GetLongValue(),
		cvss3x.Cvss3xEnvironmental.ModifiedIntegrity.GetScore())
	fmt.Printf("      - 修改可用性(MA): %s (%.2f)\n",
		cvss3x.Cvss3xEnvironmental.ModifiedAvailability.GetLongValue(),
		cvss3x.Cvss3xEnvironmental.ModifiedAvailability.GetScore())
}
