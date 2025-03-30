package main

import (
	"fmt"
	"log"

	"github.com/scagogogo/cvss-parser/pkg/cvss"
	"github.com/scagogogo/cvss-parser/pkg/parser"
)

func main() {
	// =====================================================
	// CVSS向量比较示例
	// 展示如何比较不同CVSS向量之间的差异
	// =====================================================

	fmt.Println("CVSS向量比较示例")
	fmt.Println("=====================================================")

	// 定义一组CVSS向量用于比较
	vectors := []struct {
		name   string
		vector string
	}{
		{
			name:   "网络攻击(关键)",
			vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		},
		{
			name:   "网络攻击(高)",
			vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
		},
		{
			name:   "本地攻击(高)",
			vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
		},
		{
			name:   "物理攻击(中)",
			vector: "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:H/I:L/A:L",
		},
		{
			name:   "网络攻击(低)",
			vector: "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N",
		},
		{
			name:   "含时间指标的向量",
			vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:T/RC:C",
		},
		{
			name:   "含环境指标的向量",
			vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:H/IR:M/AR:L",
		},
	}

	// 解析所有向量
	parsedVectors := make([]*cvss.Cvss3x, 0, len(vectors))
	for _, v := range vectors {
		p := parser.NewCvss3xParser(v.vector)
		cvss3x, err := p.Parse()
		if err != nil {
			log.Printf("解析失败: %v\n", err)
			continue
		}
		parsedVectors = append(parsedVectors, cvss3x)
	}

	// 使用不同的距离度量方法比较向量
	fmt.Println("\n1. 使用不同的距离度量方法比较向量")
	compareVectorsWithAllMethods(parsedVectors, vectors)

	// 比较特定向量
	fmt.Println("\n2. 比较特定向量之间的差异")
	compareSpecificVectors(parsedVectors, vectors)

	// 根据向量相似度进行分组
	fmt.Println("\n3. 根据向量相似度进行分组")
	clusterVectorsBySimilarity(parsedVectors, vectors)

	// 手动比较向量指标差异
	fmt.Println("\n4. 手动比较向量指标差异")
	compareVectorComponents(parsedVectors, vectors)

	fmt.Println("\n=====================================================")
	fmt.Println("CVSS向量比较示例结束")
}

// 使用所有距离度量方法比较向量
func compareVectorsWithAllMethods(vectors []*cvss.Cvss3x, vectorDefs []struct {
	name   string
	vector string
}) {
	fmt.Println("\n   1.1 欧几里得距离(Euclidean Distance):")
	for i := 0; i < len(vectors); i++ {
		for j := i + 1; j < len(vectors); j++ {
			// 为每对向量创建距离计算器
			distanceCalculator := cvss.NewDistanceCalculator(vectors[i], vectors[j])
			distance := distanceCalculator.EuclideanDistance()
			fmt.Printf("   - %s <-> %s: %.4f\n",
				vectorDefs[i].name, vectorDefs[j].name, distance)
		}
	}

	fmt.Println("\n   1.2 曼哈顿距离(Manhattan Distance):")
	for i := 0; i < len(vectors); i++ {
		for j := i + 1; j < len(vectors); j++ {
			distanceCalculator := cvss.NewDistanceCalculator(vectors[i], vectors[j])
			distance := distanceCalculator.ManhattanDistance()
			fmt.Printf("   - %s <-> %s: %.4f\n",
				vectorDefs[i].name, vectorDefs[j].name, distance)
		}
	}

	fmt.Println("\n   1.3 汉明距离(Hamming Distance):")
	for i := 0; i < len(vectors); i++ {
		for j := i + 1; j < len(vectors); j++ {
			distanceCalculator := cvss.NewDistanceCalculator(vectors[i], vectors[j])
			distance := distanceCalculator.HammingDistance()
			fmt.Printf("   - %s <-> %s: %d\n",
				vectorDefs[i].name, vectorDefs[j].name, distance)
		}
	}

	fmt.Println("\n   1.4 Jaccard相似度(Jaccard Similarity):")
	for i := 0; i < len(vectors); i++ {
		for j := i + 1; j < len(vectors); j++ {
			distanceCalculator := cvss.NewDistanceCalculator(vectors[i], vectors[j])
			similarity := distanceCalculator.JaccardSimilarity()
			fmt.Printf("   - %s <-> %s: %.4f\n",
				vectorDefs[i].name, vectorDefs[j].name, similarity)
		}
	}

	fmt.Println("\n   1.5 评分差异(Score Difference):")
	for i := 0; i < len(vectors); i++ {
		for j := i + 1; j < len(vectors); j++ {
			distanceCalculator := cvss.NewDistanceCalculator(vectors[i], vectors[j])
			scoreDiff := distanceCalculator.ScoreDifference()
			fmt.Printf("   - %s <-> %s: %.2f\n",
				vectorDefs[i].name, vectorDefs[j].name, scoreDiff)
		}
	}
}

// 比较特定向量之间的差异
func compareSpecificVectors(vectors []*cvss.Cvss3x, vectorDefs []struct {
	name   string
	vector string
}) {
	// 选择两个特定向量进行详细比较
	if len(vectors) < 3 {
		return
	}

	fmt.Println("\n   2.1 基本指标比较")
	compareBaseComponents(vectors[0], vectors[2], vectorDefs[0].name, vectorDefs[2].name)

	// 比较带有时间指标和不带时间指标的向量
	if len(vectors) >= 6 {
		fmt.Println("\n   2.2 带时间指标与不带时间指标的向量比较")
		compareTemporalComponents(vectors[0], vectors[5], vectorDefs[0].name, vectorDefs[5].name)
	}

	// 比较带有环境指标和不带环境指标的向量
	if len(vectors) >= 7 {
		fmt.Println("\n   2.3 带环境指标与不带环境指标的向量比较")
		compareEnvironmentalComponents(vectors[0], vectors[6], vectorDefs[0].name, vectorDefs[6].name)
	}
}

// 比较基本指标差异
func compareBaseComponents(cvss1, cvss2 *cvss.Cvss3x, name1, name2 string) {
	if cvss1.Cvss3xBase == nil || cvss2.Cvss3xBase == nil {
		return
	}

	// 计算评分差异
	calculator := cvss.NewCalculator(cvss1)
	score1, _ := calculator.Calculate()
	severity1 := calculator.GetSeverityRating(score1)

	calculator = cvss.NewCalculator(cvss2)
	score2, _ := calculator.Calculate()
	severity2 := calculator.GetSeverityRating(score2)

	fmt.Printf("   %s (%.1f - %s) vs %s (%.1f - %s)\n",
		name1, score1, severity1, name2, score2, severity2)
	fmt.Printf("   评分差异: %.2f\n", score1-score2)

	// 比较各个指标
	fmt.Println("   指标差异:")

	// 攻击向量(AV)
	if cvss1.Cvss3xBase.AttackVector != cvss2.Cvss3xBase.AttackVector {
		fmt.Printf("   - 攻击向量(AV): %s vs %s\n",
			cvss1.Cvss3xBase.AttackVector.GetLongValue(),
			cvss2.Cvss3xBase.AttackVector.GetLongValue())
	}

	// 攻击复杂性(AC)
	if cvss1.Cvss3xBase.AttackComplexity != cvss2.Cvss3xBase.AttackComplexity {
		fmt.Printf("   - 攻击复杂性(AC): %s vs %s\n",
			cvss1.Cvss3xBase.AttackComplexity.GetLongValue(),
			cvss2.Cvss3xBase.AttackComplexity.GetLongValue())
	}

	// 权限要求(PR)
	if cvss1.Cvss3xBase.PrivilegesRequired != cvss2.Cvss3xBase.PrivilegesRequired {
		fmt.Printf("   - 权限要求(PR): %s vs %s\n",
			cvss1.Cvss3xBase.PrivilegesRequired.GetLongValue(),
			cvss2.Cvss3xBase.PrivilegesRequired.GetLongValue())
	}

	// 用户交互(UI)
	if cvss1.Cvss3xBase.UserInteraction != cvss2.Cvss3xBase.UserInteraction {
		fmt.Printf("   - 用户交互(UI): %s vs %s\n",
			cvss1.Cvss3xBase.UserInteraction.GetLongValue(),
			cvss2.Cvss3xBase.UserInteraction.GetLongValue())
	}

	// 范围(S)
	if cvss1.Cvss3xBase.Scope != cvss2.Cvss3xBase.Scope {
		fmt.Printf("   - 范围(S): %s vs %s\n",
			cvss1.Cvss3xBase.Scope.GetLongValue(),
			cvss2.Cvss3xBase.Scope.GetLongValue())
	}

	// 机密性(C)
	if cvss1.Cvss3xBase.Confidentiality != cvss2.Cvss3xBase.Confidentiality {
		fmt.Printf("   - 机密性(C): %s vs %s\n",
			cvss1.Cvss3xBase.Confidentiality.GetLongValue(),
			cvss2.Cvss3xBase.Confidentiality.GetLongValue())
	}

	// 完整性(I)
	if cvss1.Cvss3xBase.Integrity != cvss2.Cvss3xBase.Integrity {
		fmt.Printf("   - 完整性(I): %s vs %s\n",
			cvss1.Cvss3xBase.Integrity.GetLongValue(),
			cvss2.Cvss3xBase.Integrity.GetLongValue())
	}

	// 可用性(A)
	if cvss1.Cvss3xBase.Availability != cvss2.Cvss3xBase.Availability {
		fmt.Printf("   - 可用性(A): %s vs %s\n",
			cvss1.Cvss3xBase.Availability.GetLongValue(),
			cvss2.Cvss3xBase.Availability.GetLongValue())
	}
}

// 比较时间指标差异
func compareTemporalComponents(cvss1, cvss2 *cvss.Cvss3x, name1, name2 string) {
	if cvss2.Cvss3xTemporal == nil {
		fmt.Printf("   %s 没有时间指标\n", name2)
		return
	}

	// 计算评分差异
	calculator := cvss.NewCalculator(cvss1)
	score1, _ := calculator.Calculate()
	severity1 := calculator.GetSeverityRating(score1)

	calculator = cvss.NewCalculator(cvss2)
	score2, _ := calculator.Calculate()
	severity2 := calculator.GetSeverityRating(score2)

	fmt.Printf("   %s (%.1f - %s) vs %s (%.1f - %s)\n",
		name1, score1, severity1, name2, score2, severity2)
	fmt.Printf("   评分差异: %.2f\n", score1-score2)

	// 显示时间指标
	fmt.Println("   时间指标:")

	// 漏洞利用代码成熟度(E)
	if cvss2.Cvss3xTemporal.ExploitCodeMaturity != nil {
		fmt.Printf("   - 漏洞利用代码成熟度(E): %s (%.2f)\n",
			cvss2.Cvss3xTemporal.ExploitCodeMaturity.GetLongValue(),
			cvss2.Cvss3xTemporal.ExploitCodeMaturity.GetScore())
	}

	// 修复级别(RL)
	if cvss2.Cvss3xTemporal.RemediationLevel != nil {
		fmt.Printf("   - 修复级别(RL): %s (%.2f)\n",
			cvss2.Cvss3xTemporal.RemediationLevel.GetLongValue(),
			cvss2.Cvss3xTemporal.RemediationLevel.GetScore())
	}

	// 报告置信度(RC)
	if cvss2.Cvss3xTemporal.ReportConfidence != nil {
		fmt.Printf("   - 报告置信度(RC): %s (%.2f)\n",
			cvss2.Cvss3xTemporal.ReportConfidence.GetLongValue(),
			cvss2.Cvss3xTemporal.ReportConfidence.GetScore())
	}
}

// 比较环境指标差异
func compareEnvironmentalComponents(cvss1, cvss2 *cvss.Cvss3x, name1, name2 string) {
	if cvss2.Cvss3xEnvironmental == nil {
		fmt.Printf("   %s 没有环境指标\n", name2)
		return
	}

	// 计算评分差异
	calculator := cvss.NewCalculator(cvss1)
	score1, _ := calculator.Calculate()
	severity1 := calculator.GetSeverityRating(score1)

	calculator = cvss.NewCalculator(cvss2)
	score2, _ := calculator.Calculate()
	severity2 := calculator.GetSeverityRating(score2)

	fmt.Printf("   %s (%.1f - %s) vs %s (%.1f - %s)\n",
		name1, score1, severity1, name2, score2, severity2)
	fmt.Printf("   评分差异: %.2f\n", score1-score2)

	// 显示环境指标
	fmt.Println("   环境指标:")

	// CIA需求
	if cvss2.Cvss3xEnvironmental.ConfidentialityRequirement != nil {
		fmt.Printf("   - 机密性需求(CR): %s (%.2f)\n",
			cvss2.Cvss3xEnvironmental.ConfidentialityRequirement.GetLongValue(),
			cvss2.Cvss3xEnvironmental.ConfidentialityRequirement.GetScore())
	}

	if cvss2.Cvss3xEnvironmental.IntegrityRequirement != nil {
		fmt.Printf("   - 完整性需求(IR): %s (%.2f)\n",
			cvss2.Cvss3xEnvironmental.IntegrityRequirement.GetLongValue(),
			cvss2.Cvss3xEnvironmental.IntegrityRequirement.GetScore())
	}

	if cvss2.Cvss3xEnvironmental.AvailabilityRequirement != nil {
		fmt.Printf("   - 可用性需求(AR): %s (%.2f)\n",
			cvss2.Cvss3xEnvironmental.AvailabilityRequirement.GetLongValue(),
			cvss2.Cvss3xEnvironmental.AvailabilityRequirement.GetScore())
	}

	// 修改的攻击指标
	if cvss2.Cvss3xEnvironmental.ModifiedAttackVector != nil {
		fmt.Printf("   - 修改攻击向量(MAV): %s (%.2f)\n",
			cvss2.Cvss3xEnvironmental.ModifiedAttackVector.GetLongValue(),
			cvss2.Cvss3xEnvironmental.ModifiedAttackVector.GetScore())
	}

	// 其他修改的指标...
}

// 根据向量相似度进行分组
func clusterVectorsBySimilarity(vectors []*cvss.Cvss3x, vectorDefs []struct {
	name   string
	vector string
}) {
	// 这里使用一个简单的分组算法，将相似度大于阈值的向量分为一组
	threshold := 0.7 // 相似度阈值

	// 创建组
	groups := make([][]int, 0)
	grouped := make([]bool, len(vectors))

	for i := 0; i < len(vectors); i++ {
		if grouped[i] {
			continue
		}

		// 创建新组
		group := []int{i}
		grouped[i] = true

		// 找与当前向量相似的其他向量
		for j := 0; j < len(vectors); j++ {
			if i == j || grouped[j] {
				continue
			}

			// 计算Jaccard相似度
			distanceCalculator := cvss.NewDistanceCalculator(vectors[i], vectors[j])
			similarity := distanceCalculator.JaccardSimilarity()
			if similarity >= threshold {
				group = append(group, j)
				grouped[j] = true
			}
		}

		groups = append(groups, group)
	}

	// 显示分组结果
	fmt.Printf("   根据Jaccard相似度(阈值: %.2f)分组结果:\n", threshold)
	for i, group := range groups {
		fmt.Printf("\n   组 %d:\n", i+1)
		for _, idx := range group {
			fmt.Printf("   - %s\n", vectorDefs[idx].name)
		}
	}
}

// 手动比较向量各组件差异
func compareVectorComponents(vectors []*cvss.Cvss3x, vectorDefs []struct {
	name   string
	vector string
}) {
	if len(vectors) < 2 {
		return
	}

	// 选择两个向量进行详细的组件比较
	v1 := vectors[0]
	v2 := vectors[1]
	name1 := vectorDefs[0].name
	name2 := vectorDefs[1].name

	fmt.Printf("\n   手动比较 %s 和 %s 的组件差异:\n", name1, name2)

	// 基础向量组件比较
	fmt.Println("\n   基础指标得分比较:")
	if v1.Cvss3xBase != nil && v2.Cvss3xBase != nil {
		compareVectorScore(
			"攻击向量(AV)",
			v1.Cvss3xBase.AttackVector.GetScore(),
			v2.Cvss3xBase.AttackVector.GetScore(),
			v1.Cvss3xBase.AttackVector.GetLongValue(),
			v2.Cvss3xBase.AttackVector.GetLongValue())

		compareVectorScore(
			"攻击复杂性(AC)",
			v1.Cvss3xBase.AttackComplexity.GetScore(),
			v2.Cvss3xBase.AttackComplexity.GetScore(),
			v1.Cvss3xBase.AttackComplexity.GetLongValue(),
			v2.Cvss3xBase.AttackComplexity.GetLongValue())

		compareVectorScore(
			"权限要求(PR)",
			v1.Cvss3xBase.PrivilegesRequired.GetScore(),
			v2.Cvss3xBase.PrivilegesRequired.GetScore(),
			v1.Cvss3xBase.PrivilegesRequired.GetLongValue(),
			v2.Cvss3xBase.PrivilegesRequired.GetLongValue())

		compareVectorScore(
			"用户交互(UI)",
			v1.Cvss3xBase.UserInteraction.GetScore(),
			v2.Cvss3xBase.UserInteraction.GetScore(),
			v1.Cvss3xBase.UserInteraction.GetLongValue(),
			v2.Cvss3xBase.UserInteraction.GetLongValue())

		compareVectorScore(
			"范围(S)",
			v1.Cvss3xBase.Scope.GetScore(),
			v2.Cvss3xBase.Scope.GetScore(),
			v1.Cvss3xBase.Scope.GetLongValue(),
			v2.Cvss3xBase.Scope.GetLongValue())

		compareVectorScore(
			"机密性(C)",
			v1.Cvss3xBase.Confidentiality.GetScore(),
			v2.Cvss3xBase.Confidentiality.GetScore(),
			v1.Cvss3xBase.Confidentiality.GetLongValue(),
			v2.Cvss3xBase.Confidentiality.GetLongValue())

		compareVectorScore(
			"完整性(I)",
			v1.Cvss3xBase.Integrity.GetScore(),
			v2.Cvss3xBase.Integrity.GetScore(),
			v1.Cvss3xBase.Integrity.GetLongValue(),
			v2.Cvss3xBase.Integrity.GetLongValue())

		compareVectorScore(
			"可用性(A)",
			v1.Cvss3xBase.Availability.GetScore(),
			v2.Cvss3xBase.Availability.GetScore(),
			v1.Cvss3xBase.Availability.GetLongValue(),
			v2.Cvss3xBase.Availability.GetLongValue())
	}

	// 计算总评分
	calculator1 := cvss.NewCalculator(v1)
	score1, _ := calculator1.Calculate()
	severity1 := calculator1.GetSeverityRating(score1)

	calculator2 := cvss.NewCalculator(v2)
	score2, _ := calculator2.Calculate()
	severity2 := calculator2.GetSeverityRating(score2)

	fmt.Printf("\n   总评分比较:\n")
	fmt.Printf("   - %s: %.1f (%s)\n", name1, score1, severity1)
	fmt.Printf("   - %s: %.1f (%s)\n", name2, score2, severity2)
	fmt.Printf("   - 差异: %.2f\n", score1-score2)
}

// 比较向量组件分数
func compareVectorScore(name string, score1, score2 float64, value1, value2 string) {
	fmt.Printf("   - %s:\n", name)
	fmt.Printf("     值: %s vs %s\n", value1, value2)
	fmt.Printf("     分数: %.2f vs %.2f (差异: %.2f)\n",
		score1, score2, score1-score2)

	// 添加比较指示符
	if score1 > score2 {
		fmt.Printf("     比较: 第一个向量的%s更高 ⬆️\n", name)
	} else if score1 < score2 {
		fmt.Printf("     比较: 第二个向量的%s更高 ⬇️\n", name)
	} else {
		fmt.Printf("     比较: 两个向量的%s相同 =\n", name)
	}
}
