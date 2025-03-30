package main

import (
	"fmt"
	"log"

	"github.com/scagogogo/cvss-parser/pkg/cvss"
	"github.com/scagogogo/cvss-parser/pkg/parser"
)

func main() {
	// 示例CVSS向量字符串
	cvssVector := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

	// 创建解析器
	p := parser.NewCvss3xParser(cvssVector)

	// 解析CVSS向量
	cvss3x, err := p.Parse()
	if err != nil {
		log.Fatalf("解析CVSS向量失败: %v", err)
	}

	// 打印解析结果
	fmt.Printf("CVSS版本: %d.%d\n", cvss3x.MajorVersion, cvss3x.MinorVersion)
	fmt.Printf("攻击向量(AV): %s\n", cvss3x.Cvss3xBase.AttackVector.GetLongValue())
	fmt.Printf("攻击复杂性(AC): %s\n", cvss3x.Cvss3xBase.AttackComplexity.GetLongValue())
	fmt.Printf("权限要求(PR): %s\n", cvss3x.Cvss3xBase.PrivilegesRequired.GetLongValue())
	fmt.Printf("用户交互(UI): %s\n", cvss3x.Cvss3xBase.UserInteraction.GetLongValue())
	fmt.Printf("范围(S): %s\n", cvss3x.Cvss3xBase.Scope.GetLongValue())
	fmt.Printf("机密性(C): %s\n", cvss3x.Cvss3xBase.Confidentiality.GetLongValue())
	fmt.Printf("完整性(I): %s\n", cvss3x.Cvss3xBase.Integrity.GetLongValue())
	fmt.Printf("可用性(A): %s\n", cvss3x.Cvss3xBase.Availability.GetLongValue())

	// 创建计算器并计算CVSS评分
	calculator := cvss.NewCalculator(cvss3x)
	score, err := calculator.Calculate()
	if err != nil {
		log.Fatalf("计算CVSS评分失败: %v", err)
	}

	// 获取严重性等级
	severity := calculator.GetSeverityRating(score)

	fmt.Printf("\nCVSS评分: %.1f\n", score)
	fmt.Printf("严重性等级: %s\n", severity)

	// 将CVSS对象转换回向量字符串
	fmt.Printf("\n原始向量: %s\n", cvssVector)
	fmt.Printf("重构向量: %s\n", cvss3x.String())
}
