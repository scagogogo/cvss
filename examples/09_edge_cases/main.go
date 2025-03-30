package main

import (
	"fmt"

	"github.com/scagogogo/cvss-parser/pkg/cvss"
	"github.com/scagogogo/cvss-parser/pkg/parser"
)

func main() {
	// =====================================================
	// CVSS边缘情况处理示例
	// 展示如何处理各种CVSS向量的边缘情况
	// =====================================================

	fmt.Println("CVSS边缘情况处理示例")
	fmt.Println("=====================================================")

	// 1. 处理不完整的向量
	fmt.Println("\n1. 处理不完整的向量")
	handleIncompleteVectors()

	// 2. 处理版本兼容性
	fmt.Println("\n2. 处理版本兼容性")
	handleVersionCompatibility()

	// 3. 处理无效的向量
	fmt.Println("\n3. 处理无效的向量")
	handleInvalidVectors()

	// 4. 处理边缘评分情况
	fmt.Println("\n4. 处理边缘评分情况")
	handleEdgeScores()

	// 5. 防御性编程示例
	fmt.Println("\n5. 防御性编程示例")
	defensiveProgramming()

	fmt.Println("\n=====================================================")
	fmt.Println("CVSS边缘情况处理示例结束")
}

// handleIncompleteVectors 演示如何处理不完整的CVSS向量
func handleIncompleteVectors() {
	// 缺少某些必需的基本指标的向量
	incompleteVectors := []struct {
		name   string
		vector string
		issue  string
	}{
		{
			name:   "缺少攻击向量(AV)",
			vector: "CVSS:3.1/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			issue:  "缺少必需的攻击向量(AV)指标",
		},
		{
			name:   "缺少攻击复杂性(AC)",
			vector: "CVSS:3.1/AV:N/PR:N/UI:N/S:U/C:H/I:H/A:H",
			issue:  "缺少必需的攻击复杂性(AC)指标",
		},
		{
			name:   "缺少机密性(C)",
			vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/I:H/A:H",
			issue:  "缺少必需的机密性(C)指标",
		},
		{
			name:   "只有版本信息",
			vector: "CVSS:3.1",
			issue:  "只有版本信息，没有任何指标",
		},
	}

	for _, iv := range incompleteVectors {
		fmt.Printf("   %s:\n", iv.name)
		fmt.Printf("   向量: %s\n", iv.vector)
		fmt.Printf("   问题: %s\n", iv.issue)

		// 尝试解析
		p := parser.NewCvss3xParser(iv.vector)
		cvss3x, err := p.Parse()

		if err != nil {
			fmt.Printf("   解析结果: 失败 - %v\n", err)
		} else {
			fmt.Printf("   解析结果: 成功 (这可能意味着解析器对缺失指标使用了默认值)\n")

			// 尝试计算评分
			calculator := cvss.NewCalculator(cvss3x)
			score, scoreErr := calculator.Calculate()

			if scoreErr != nil {
				fmt.Printf("   评分计算: 失败 - %v\n", scoreErr)
			} else {
				fmt.Printf("   评分: %.1f (%s)\n", score, calculator.GetSeverityRating(score))
			}
		}

		// 提供修复建议
		fmt.Printf("   建议: 添加缺失的必需指标或使用默认值\n\n")
	}

	// 演示如何手动处理不完整向量
	fmt.Println("   处理不完整向量的方法:")
	fmt.Println("   1. 使用默认值填充缺失的指标")
	fmt.Println("   2. 在解析之前验证向量格式")
	fmt.Println("   3. 使用错误处理来优雅地处理解析失败")

	// 示例：使用默认值填充缺失的指标
	fmt.Println("\n   示例：使用默认值填充缺失的指标")
	incompleteVector := "CVSS:3.1/AV:N/AC:L/PR:N/S:U/C:H"
	fmt.Printf("   不完整向量: %s\n", incompleteVector)

	// 添加默认值
	completeVector := incompleteVector + "/I:N/A:N"
	fmt.Printf("   使用默认值完成后: %s\n", completeVector)

	// 解析完整的向量
	p := parser.NewCvss3xParser(completeVector)
	cvss3x, _ := p.Parse()
	calculator := cvss.NewCalculator(cvss3x)
	score, _ := calculator.Calculate()

	fmt.Printf("   评分: %.1f (%s)\n", score, calculator.GetSeverityRating(score))
}

// handleVersionCompatibility 演示如何处理不同CVSS版本的兼容性
func handleVersionCompatibility() {
	// 不同CVSS版本的向量
	versionVectors := []struct {
		name    string
		vector  string
		version string
	}{
		{
			name:    "CVSS 3.1",
			vector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			version: "3.1",
		},
		{
			name:    "CVSS 3.0",
			vector:  "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			version: "3.0",
		},
		{
			name:    "缺少版本信息",
			vector:  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			version: "未知",
		},
		{
			name:    "无效版本号",
			vector:  "CVSS:X.Y/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			version: "X.Y",
		},
	}

	for _, vv := range versionVectors {
		fmt.Printf("   %s:\n", vv.name)
		fmt.Printf("   向量: %s\n", vv.vector)

		// 尝试解析
		p := parser.NewCvss3xParser(vv.vector)
		cvss3x, err := p.Parse()

		if err != nil {
			fmt.Printf("   解析结果: 失败 - %v\n", err)
			fmt.Printf("   建议: 使用有效的CVSS版本格式\n\n")
			continue
		}

		// 输出版本信息
		fmt.Printf("   解析版本: %d.%d\n", cvss3x.MajorVersion, cvss3x.MinorVersion)

		// 计算评分
		calculator := cvss.NewCalculator(cvss3x)
		score, scoreErr := calculator.Calculate()

		if scoreErr != nil {
			fmt.Printf("   评分计算: 失败 - %v\n", scoreErr)
		} else {
			fmt.Printf("   评分: %.1f (%s)\n", score, calculator.GetSeverityRating(score))
		}

		fmt.Println()
	}

	// 版本兼容性处理建议
	fmt.Println("   版本兼容性处理建议:")
	fmt.Println("   1. 始终指定并检查CVSS版本")
	fmt.Println("   2. 在不确定版本时使用最佳猜测或默认版本")
	fmt.Println("   3. 对不同版本的计算公式进行适当处理")
}

// handleInvalidVectors 演示如何处理无效的CVSS向量
func handleInvalidVectors() {
	// 各种无效的向量
	invalidVectors := []struct {
		name   string
		vector string
		issue  string
	}{
		{
			name:   "无效指标值",
			vector: "CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			issue:  "AV:Z 不是有效的攻击向量值",
		},
		{
			name:   "重复指标",
			vector: "CVSS:3.1/AV:N/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			issue:  "攻击向量(AV)出现两次",
		},
		{
			name:   "格式错误",
			vector: "CVSS:3.1/AV=N/AC=L/PR=N/UI=N/S=U/C=H/I=H/A=H",
			issue:  "使用了等号(=)而不是冒号(:)",
		},
		{
			name:   "无法识别的指标",
			vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/XX:YY",
			issue:  "包含未知指标XX:YY",
		},
		{
			name:   "空向量",
			vector: "",
			issue:  "向量为空",
		},
		{
			name:   "非CVSS字符串",
			vector: "这不是一个CVSS向量",
			issue:  "不符合CVSS格式",
		},
	}

	for _, iv := range invalidVectors {
		fmt.Printf("   %s:\n", iv.name)
		fmt.Printf("   向量: %s\n", iv.vector)
		fmt.Printf("   问题: %s\n", iv.issue)

		// 尝试解析
		p := parser.NewCvss3xParser(iv.vector)
		_, err := p.Parse()

		fmt.Printf("   解析结果: %v\n", err)
		fmt.Printf("   建议: 验证并修正向量格式和值\n\n")
	}

	// 无效向量处理建议
	fmt.Println("   处理无效向量的建议:")
	fmt.Println("   1. 实施健壮的输入验证")
	fmt.Println("   2. 提供有用的错误消息来帮助纠正问题")
	fmt.Println("   3. 考虑使用回退或默认值进行优雅降级")
}

// handleEdgeScores 演示如何处理极端评分情况
func handleEdgeScores() {
	// 边缘评分情况
	edgeScoreVectors := []struct {
		name        string
		vector      string
		description string
	}{
		{
			name:        "最高评分(10.0)",
			vector:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
			description: "网络攻击，低复杂度，无权限，无用户交互，改变范围，高CIA影响",
		},
		{
			name:        "最低评分(0.0)",
			vector:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
			description: "零CIA影响的向量总是得分为0.0",
		},
		{
			name:        "高范围变化(9.9)",
			vector:      "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
			description: "与最高评分类似，但需要低权限",
		},
		{
			name:        "极低评分(0.1)",
			vector:      "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:L",
			description: "物理访问，高复杂度，高权限要求，需用户交互，仅有低可用性影响",
		},
	}

	for _, ev := range edgeScoreVectors {
		fmt.Printf("   %s:\n", ev.name)
		fmt.Printf("   向量: %s\n", ev.vector)
		fmt.Printf("   描述: %s\n", ev.description)

		// 解析并计算评分
		p := parser.NewCvss3xParser(ev.vector)
		cvss3x, _ := p.Parse()
		calculator := cvss.NewCalculator(cvss3x)
		score, _ := calculator.Calculate()
		severity := calculator.GetSeverityRating(score)

		fmt.Printf("   评分: %.1f (%s)\n\n", score, severity)
	}

	// 边缘情况的处理建议
	fmt.Println("   处理边缘评分情况的建议:")
	fmt.Println("   1. 了解CVSS评分的范围和限制")
	fmt.Println("   2. 确保UI能够适当显示极端评分")
	fmt.Println("   3. 考虑评分为0.0的特殊处理")
}

// defensiveProgramming 演示处理CVSS向量时的防御性编程实践
func defensiveProgramming() {
	// 示例1：安全解析向量
	fmt.Println("   示例1：安全解析向量")
	vector := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	fmt.Printf("   向量: %s\n", vector)

	cvss3x, err := safeParseVector(vector)
	if err != nil {
		fmt.Printf("   解析失败: %v\n", err)
	} else {
		fmt.Println("   解析成功")

		// 使用解析结果计算评分
		score, severity := safeCalculateScore(cvss3x)
		fmt.Printf("   评分: %.1f (%s)\n", score, severity)
	}

	// 示例2：处理无效输入
	fmt.Println("\n   示例2：处理无效输入")
	invalidVector := "无效向量"
	fmt.Printf("   向量: %s\n", invalidVector)

	cvss3x, err = safeParseVector(invalidVector)
	if err != nil {
		fmt.Printf("   解析失败: %v\n", err)
		fmt.Println("   使用默认向量作为回退...")

		// 使用默认向量作为回退
		defaultVector := "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L"
		fmt.Printf("   默认向量: %s\n", defaultVector)

		cvss3x, _ = safeParseVector(defaultVector)
		score, severity := safeCalculateScore(cvss3x)
		fmt.Printf("   评分: %.1f (%s)\n", score, severity)
	}

	// 示例3：验证CVSS向量字符串
	fmt.Println("\n   示例3：验证CVSS向量字符串")

	testVectors := []string{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // 有效向量
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",     // 不完整向量
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:Z/I:H/A:H", // 无效值
	}

	for i, testVector := range testVectors {
		fmt.Printf("   测试向量 %d: %s\n", i+1, testVector)
		isValid := isValidVectorString(testVector)
		fmt.Printf("   有效性: %v\n\n", isValid)
	}

	// 防御性编程总结
	fmt.Println("\n   防御性编程最佳实践:")
	fmt.Println("   1. 始终验证输入并优雅处理错误")
	fmt.Println("   2. 使用安全的包装函数来处理潜在的错误")
	fmt.Println("   3. 实施回退机制以在发生错误时提供合理的默认值")
	fmt.Println("   4. 验证向量字符串以确保其符合预期格式")
}

// safeParseVector 安全地解析CVSS向量，处理所有潜在错误
func safeParseVector(vectorStr string) (*cvss.Cvss3x, error) {
	// 检查输入
	if vectorStr == "" {
		return nil, fmt.Errorf("向量字符串为空")
	}

	// 尝试解析
	p := parser.NewCvss3xParser(vectorStr)
	return p.Parse()
}

// safeCalculateScore 安全地计算CVSS评分，处理潜在错误
func safeCalculateScore(cvss3x *cvss.Cvss3x) (float64, string) {
	// 检查输入
	if cvss3x == nil {
		return 0.0, "None"
	}

	// 创建计算器
	calculator := cvss.NewCalculator(cvss3x)

	// 尝试计算评分
	score, err := calculator.Calculate()
	if err != nil {
		return 0.0, "None"
	}

	// 获取严重性级别
	severity := calculator.GetSeverityRating(score)
	return score, severity
}

// isValidVectorString 检查向量字符串是否有效
func isValidVectorString(vectorStr string) bool {
	// 检查空字符串
	if vectorStr == "" {
		return false
	}

	// 检查是否以CVSS:开头
	if len(vectorStr) < 6 || vectorStr[:5] != "CVSS:" {
		return false
	}

	// 尝试解析，只要能解析成功，就认为是有效的
	p := parser.NewCvss3xParser(vectorStr)
	_, err := p.Parse()
	return err == nil
}

// isValidCvss 验证CVSS对象是否有效
func isValidCvss(cvss3x *cvss.Cvss3x) bool {
	if cvss3x == nil {
		return false
	}

	// 检查版本
	if cvss3x.MajorVersion <= 0 {
		return false
	}

	// 检查基础指标
	if cvss3x.Cvss3xBase == nil {
		return false
	}

	// 检查所有必需的基础指标是否存在
	if cvss3x.Cvss3xBase.AttackVector == nil ||
		cvss3x.Cvss3xBase.AttackComplexity == nil ||
		cvss3x.Cvss3xBase.PrivilegesRequired == nil ||
		cvss3x.Cvss3xBase.UserInteraction == nil ||
		cvss3x.Cvss3xBase.Scope == nil ||
		cvss3x.Cvss3xBase.Confidentiality == nil ||
		cvss3x.Cvss3xBase.Integrity == nil ||
		cvss3x.Cvss3xBase.Availability == nil {
		return false
	}

	return true
}
