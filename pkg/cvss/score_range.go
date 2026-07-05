package cvss

import (
	"fmt"
	"math"

	"github.com/scagogogo/cvss-skills/pkg/vector"
)

// ScoreRange 表示部分向量的评分范围
type ScoreRange struct {
	MinScore     float64  // 可能的最低评分
	MaxScore     float64  // 可能的最高评分
	MinSeverity  Severity // 最低严重性
	MaxSeverity  Severity // 最高严重性
	IsComplete   bool     // 是否所有基础指标都已设置
	MissingCount int      // 缺失的基础指标数量
}

// String 返回评分范围的可读表示
func (sr ScoreRange) String() string {
	if sr.IsComplete {
		return fmt.Sprintf("%.1f (%s) [complete]", sr.MinScore, sr.MinSeverity)
	}
	return fmt.Sprintf("%.1f (%s) ~ %.1f (%s) [%d metrics missing]",
		sr.MinScore, sr.MinSeverity, sr.MaxScore, sr.MaxSeverity, sr.MissingCount)
}

// GetScoreRange 计算部分向量的评分范围
// 对于缺失的基础指标，计算所有可能值的最高和最低评分
//
// 用法:
//
//	partial, _ := parser.ParseString("CVSS:3.1/AV:N/AC:L")  // only 2 of 8 metrics
//	rng := cvss.GetScoreRange(partial)
//	fmt.Printf("Score range: %.1f ~ %.1f\n", rng.MinScore, rng.MaxScore)
func GetScoreRange(cv *Cvss3x) ScoreRange {
	if cv == nil || cv.Cvss3xBase == nil {
		return ScoreRange{MinScore: 0, MaxScore: 10, MinSeverity: SeverityNone, MaxSeverity: SeverityCritical, MissingCount: 8}
	}

	// 统计缺失的基础指标
	missing := cv.MissingMetrics()
	missingCount := len(missing)

	if missingCount == 0 {
		// 完整向量，直接计算
		calc := NewCalculator(cv)
		score, err := calc.GetBaseScore()
		if err != nil {
			return ScoreRange{MinScore: 0, MaxScore: 10, MissingCount: 0}
		}
		return ScoreRange{
			MinScore:    score,
			MaxScore:    score,
			MinSeverity: GetSeverity(score),
			MaxSeverity: GetSeverity(score),
			IsComplete:  true,
		}
	}

	// 对缺失指标，穷举所有组合找 min/max
	minScore, maxScore := findMinMaxScore(cv, missing)

	return ScoreRange{
		MinScore:     minScore,
		MaxScore:     maxScore,
		MinSeverity:  GetSeverity(minScore),
		MaxSeverity:  GetSeverity(maxScore),
		IsComplete:   false,
		MissingCount: missingCount,
	}
}

// findMinMaxScore 穷举缺失指标的所有组合，找出最高和最低评分
func findMinMaxScore(cv *Cvss3x, missing []string) (float64, float64) {
	metricValues := map[string][]rune{
		"AV": {'N', 'A', 'L', 'P'},
		"AC": {'L', 'H'},
		"PR": {'N', 'L', 'H'},
		"UI": {'N', 'R'},
		"S":  {'U', 'C'},
		"C":  {'H', 'L', 'N'},
		"I":  {'H', 'L', 'N'},
		"A":  {'H', 'L', 'N'},
	}

	minScore := 10.0
	maxScore := 0.0

	// 使用递归穷举所有组合
	var tryCombinations func(int, *Cvss3x)
	tryCombinations = func(idx int, current *Cvss3x) {
		if idx >= len(missing) {
			// 所有缺失指标都已填充，向量完整，GetBaseScore 不会失败
			calc := NewCalculator(current)
			score, _ := calc.GetBaseScore()
			if score < minScore {
				minScore = score
			}
			if score > maxScore {
				maxScore = score
			}
			return
		}

		metric := missing[idx]
		values := metricValues[metric]

		for _, val := range values {
			next := current.Clone()
			switch metric {
			case "AV":
				next.Cvss3xBase.AttackVector, _ = vector.GetAttackVector(val)
			case "AC":
				next.Cvss3xBase.AttackComplexity, _ = vector.GetAttackComplexity(val)
			case "PR":
				next.Cvss3xBase.PrivilegesRequired, _ = vector.GetPrivilegesRequired(val)
			case "UI":
				next.Cvss3xBase.UserInteraction, _ = vector.GetUserInteraction(val)
			case "S":
				next.Cvss3xBase.Scope, _ = vector.GetScope(val)
			case "C":
				next.Cvss3xBase.Confidentiality, _ = vector.GetConfidentiality(val)
			case "I":
				next.Cvss3xBase.Integrity, _ = vector.GetIntegrity(val)
			case "A":
				next.Cvss3xBase.Availability, _ = vector.GetAvailability(val)
			}
			tryCombinations(idx+1, next)
		}
	}

	tryCombinations(0, cv)

	return minScore, maxScore
}

// GetWorstCase 计算部分向量的最坏情况（最高评分）
// 对缺失指标选择使评分最高的值
func GetWorstCase(cv *Cvss3x) (*Cvss3x, float64, error) {
	return getExtremeCase(cv, true)
}

// GetBestCase 计算部分向量的最好情况（最低评分）
// 对缺失指标选择使评分最低的值
func GetBestCase(cv *Cvss3x) (*Cvss3x, float64, error) {
	return getExtremeCase(cv, false)
}

// getExtremeCase 计算极端情况
func getExtremeCase(cv *Cvss3x, worst bool) (*Cvss3x, float64, error) {
	if cv == nil {
		return nil, 0, ErrNilReceiver
	}

	missing := cv.MissingMetrics()
	if len(missing) == 0 {
		calc := NewCalculator(cv)
		score, err := calc.GetBaseScore()
		return cv.Clone(), score, err
	}

	rng := GetScoreRange(cv)
	targetScore := rng.MaxScore
	if !worst {
		targetScore = rng.MinScore
	}

	// 穷举找最接近目标的组合
	metricValues := map[string][]rune{
		"AV": {'N', 'A', 'L', 'P'},
		"AC": {'L', 'H'},
		"PR": {'N', 'L', 'H'},
		"UI": {'N', 'R'},
		"S":  {'U', 'C'},
		"C":  {'H', 'L', 'N'},
		"I":  {'H', 'L', 'N'},
		"A":  {'H', 'L', 'N'},
	}

	var bestCv *Cvss3x
	bestDiff := 10.1

	var tryCombinations func(int, *Cvss3x)
	tryCombinations = func(idx int, current *Cvss3x) {
		if idx >= len(missing) {
			// 所有缺失指标已填充，向量完整，GetBaseScore 不会失败
			calc := NewCalculator(current)
			score, _ := calc.GetBaseScore()
			diff := math.Abs(score - targetScore)
			if diff < bestDiff {
				bestDiff = diff
				bestCv = current.Clone()
			}
			return
		}

		metric := missing[idx]
		for _, val := range metricValues[metric] {
			next := current.Clone()
			switch metric {
			case "AV":
				next.Cvss3xBase.AttackVector, _ = vector.GetAttackVector(val)
			case "AC":
				next.Cvss3xBase.AttackComplexity, _ = vector.GetAttackComplexity(val)
			case "PR":
				next.Cvss3xBase.PrivilegesRequired, _ = vector.GetPrivilegesRequired(val)
			case "UI":
				next.Cvss3xBase.UserInteraction, _ = vector.GetUserInteraction(val)
			case "S":
				next.Cvss3xBase.Scope, _ = vector.GetScope(val)
			case "C":
				next.Cvss3xBase.Confidentiality, _ = vector.GetConfidentiality(val)
			case "I":
				next.Cvss3xBase.Integrity, _ = vector.GetIntegrity(val)
			case "A":
				next.Cvss3xBase.Availability, _ = vector.GetAvailability(val)
			}
			tryCombinations(idx+1, next)
		}
	}

	tryCombinations(0, cv)

	// missing 非空时，至少一种合法组合使 GetBaseScore 成功，bestCv 必非 nil。
	calc := NewCalculator(bestCv)
	score, _ := calc.GetBaseScore()
	return bestCv, score, nil
}
