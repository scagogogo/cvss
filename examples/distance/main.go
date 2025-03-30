package main

import (
	"fmt"
	"log"

	"github.com/scagogogo/cvss-parser/pkg/cvss"
	"github.com/scagogogo/cvss-parser/pkg/parser"
)

func main() {
	// 准备两个CVSS向量字符串进行比较
	vector1 := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"               // 关键级别，9.8分
	vector2 := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L"               // 略有不同，9.1分
	vector3 := "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L"               // 低级别，~3.0分
	vector4 := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"               // 最高级别，10.0分
	vector5 := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:W/RC:C" // 带时间指标

	// 解析向量
	parser1 := parser.NewCvss3xParser(vector1)
	cvss1, err := parser1.Parse()
	if err != nil {
		log.Fatalf("解析向量1失败: %v", err)
	}

	parser2 := parser.NewCvss3xParser(vector2)
	cvss2, err := parser2.Parse()
	if err != nil {
		log.Fatalf("解析向量2失败: %v", err)
	}

	parser3 := parser.NewCvss3xParser(vector3)
	cvss3, err := parser3.Parse()
	if err != nil {
		log.Fatalf("解析向量3失败: %v", err)
	}

	parser4 := parser.NewCvss3xParser(vector4)
	cvss4, err := parser4.Parse()
	if err != nil {
		log.Fatalf("解析向量4失败: %v", err)
	}

	parser5 := parser.NewCvss3xParser(vector5)
	cvss5, err := parser5.Parse()
	if err != nil {
		log.Fatalf("解析向量5失败: %v", err)
	}

	// 创建计算器计算CVSS分数
	calc1 := cvss.NewCalculator(cvss1)
	score1, _ := calc1.Calculate()

	calc2 := cvss.NewCalculator(cvss2)
	score2, _ := calc2.Calculate()

	calc3 := cvss.NewCalculator(cvss3)
	score3, _ := calc3.Calculate()

	calc4 := cvss.NewCalculator(cvss4)
	score4, _ := calc4.Calculate()

	calc5 := cvss.NewCalculator(cvss5)
	score5, _ := calc5.Calculate()

	fmt.Println("======== CVSS向量距离计算示例 ========")
	fmt.Printf("向量1: %s (分数: %.1f)\n", vector1, score1)
	fmt.Printf("向量2: %s (分数: %.1f)\n", vector2, score2)
	fmt.Printf("向量3: %s (分数: %.1f)\n", vector3, score3)
	fmt.Printf("向量4: %s (分数: %.1f)\n", vector4, score4)
	fmt.Printf("向量5: %s (分数: %.1f)\n\n", vector5, score5)

	// 创建距离计算器
	fmt.Println("1. 相似向量比较 (向量1 vs 向量2):")
	dc12 := cvss.NewDistanceCalculator(cvss1, cvss2)
	compareVectors(dc12)

	fmt.Println("\n2. 差异很大的向量比较 (向量1 vs 向量3):")
	dc13 := cvss.NewDistanceCalculator(cvss1, cvss3)
	compareVectors(dc13)

	fmt.Println("\n3. 临界值向量比较 (向量1 vs 向量4):")
	dc14 := cvss.NewDistanceCalculator(cvss1, cvss4)
	compareVectors(dc14)

	fmt.Println("\n4. 带时间指标的向量比较 (向量1 vs 向量5):")
	dc15 := cvss.NewDistanceCalculator(cvss1, cvss5)
	compareVectors(dc15)
}

// 打印向量比较结果
func compareVectors(dc *cvss.DistanceCalculator) {
	fmt.Printf("  - 欧几里得距离: %.4f\n", dc.EuclideanDistance())
	fmt.Printf("  - 曼哈顿距离: %.4f\n", dc.ManhattanDistance())
	fmt.Printf("  - 汉明距离: %d\n", dc.HammingDistance())
	fmt.Printf("  - Jaccard相似度: %.4f\n", dc.JaccardSimilarity())
	fmt.Printf("  - CVSS评分差异: %.1f\n", dc.ScoreDifference())
}
