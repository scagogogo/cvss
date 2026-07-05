package cvss

import (
	"fmt"
	"math"
	"sort"

	"github.com/scagogogo/cvss-skills/pkg/vector"
)

// MetricImpact 表示单个指标变化对评分的影响
type MetricImpact struct {
	Metric       string        // 指标短名称，如 "AV"
	CurrentVal   string        // 当前值，如 "N"
	CurrentScore float64       // 当前评分
	ValueImpacts []ValueImpact // 每个可选值的影响
}

// ValueImpact 表示某个指标值对评分的影响
type ValueImpact struct {
	Value     string   // 指标值，如 "A"
	LongValue string   // 长名称，如 "Adjacent"
	Score     float64  // 选择该值后的评分
	Delta     float64  // 与当前评分的差异（正数=升高，负数=降低）
	Severity  Severity // 选择该值后的严重性
}

// String 返回影响分析的可读表示
func (mi MetricImpact) String() string {
	s := fmt.Sprintf("%s (current: %s, score: %.1f)\n", mi.Metric, mi.CurrentVal, mi.CurrentScore)
	for _, vi := range mi.ValueImpacts {
		delta := ""
		if vi.Delta > 0 {
			delta = fmt.Sprintf("+%.1f", vi.Delta)
		} else {
			delta = fmt.Sprintf("%.1f", vi.Delta)
		}
		s += fmt.Sprintf("  %s (%s): %.1f (%s) [%s]\n", vi.Value, vi.LongValue, vi.Score, vi.Severity, delta)
	}
	return s
}

// ImpactAnalysis 对一个完整的 CVSS 向量进行影响分析
// 对每个指标，计算切换到其他值时评分的变化
// 返回按影响绝对值从大到小排序的结果
//
// 用法:
//
//	impacts := cvss.ImpactAnalysis(cv)
//	for _, mi := range impacts {
//	    fmt.Println(mi.String())
//	}
func ImpactAnalysis(cv *Cvss3x) ([]MetricImpact, error) {
	if cv == nil {
		return nil, ErrNilReceiver
	}
	if err := cv.Check(); err != nil {
		return nil, err
	}

	calc := NewCalculator(cv)
	// 入口已 Check() 通过，基础评分计算不会失败
	baseScore, _ := calc.GetBaseScore()

	// 每个基础指标的可选值
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

	// 当前值映射
	currentValues := map[string]rune{
		"AV": cv.Cvss3xBase.AttackVector.GetShortValue(),
		"AC": cv.Cvss3xBase.AttackComplexity.GetShortValue(),
		"PR": cv.Cvss3xBase.PrivilegesRequired.GetShortValue(),
		"UI": cv.Cvss3xBase.UserInteraction.GetShortValue(),
		"S":  cv.Cvss3xBase.Scope.GetShortValue(),
		"C":  cv.Cvss3xBase.Confidentiality.GetShortValue(),
		"I":  cv.Cvss3xBase.Integrity.GetShortValue(),
		"A":  cv.Cvss3xBase.Availability.GetShortValue(),
	}

	// 值到长名称的映射
	valueLongNames := getValueLongNameMap()

	var impacts []MetricImpact

	for _, metric := range []string{"AV", "AC", "PR", "UI", "S", "C", "I", "A"} {
		currentVal := string(currentValues[metric])
		mi := MetricImpact{
			Metric:       metric,
			CurrentVal:   currentVal,
			CurrentScore: baseScore,
		}

		for _, val := range metricValues[metric] {
			// 跳过当前值
			if val == currentValues[metric] {
				continue
			}

			// 创建修改后的向量（metric 与 val 均来自合法枚举，modifyBaseMetric 不会失败）
			modified, _ := modifyBaseMetric(cv, metric, val)

			modCalc := NewCalculator(modified)
			// 修改后的向量依然合法，GetBaseScore 不会失败
			modScore, _ := modCalc.GetBaseScore()

			vi := ValueImpact{
				Value:     string(val),
				LongValue: valueLongNames[metric][val],
				Score:     modScore,
				Delta:     modScore - baseScore,
				Severity:  GetSeverity(modScore),
			}
			mi.ValueImpacts = append(mi.ValueImpacts, vi)
		}

		impacts = append(impacts, mi)
	}

	// 按最大影响绝对值排序
	sort.Slice(impacts, func(i, j int) bool {
		maxI := maxAbsDelta(impacts[i].ValueImpacts)
		maxJ := maxAbsDelta(impacts[j].ValueImpacts)
		return maxI > maxJ
	})

	return impacts, nil
}

// FindMetricChangesToReachTarget 找到达到目标评分所需的最小指标变化
// 返回一组指标变化，应用后评分将最接近目标评分
//
// 用法:
//
//	changes, err := cvss.FindMetricChangesToReachTarget(cv, 7.0)
//	for _, c := range changes {
//	    fmt.Printf("Change %s from %s to %s (score: %.1f)\n", c.Metric, c.From, c.To, c.ResultScore)
//	}
func FindMetricChangesToReachTarget(cv *Cvss3x, targetScore float64) ([]MetricChange, error) {
	if cv == nil {
		return nil, ErrNilReceiver
	}
	if err := cv.Check(); err != nil {
		return nil, err
	}

	calc := NewCalculator(cv)
	// 入口已 Check() 通过，基础评分计算不会失败
	currentScore, _ := calc.GetBaseScore()

	// 如果已经达到目标（容差 0.05）
	if math.Abs(currentScore-targetScore) <= 0.05 {
		return nil, nil
	}

	// 对每个指标，尝试每个可选值，找最小变化集合
	// ImpactAnalysis 在 Check 通过后不会失败
	impacts, _ := ImpactAnalysis(cv)

	needIncrease := targetScore > currentScore

	var changes []MetricChange
	workingScore := currentScore

	for _, mi := range impacts {
		if math.Abs(workingScore-targetScore) <= 0.05 {
			break
		}

		// 找到该指标中方向正确且影响最大的值
		var bestDelta float64
		var bestValue string
		var bestScore float64
		var bestSeverity Severity

		for _, vi := range mi.ValueImpacts {
			if needIncrease && vi.Delta > bestDelta {
				bestDelta = vi.Delta
				bestValue = vi.Value
				bestScore = vi.Score
				bestSeverity = vi.Severity
			} else if !needIncrease && vi.Delta < bestDelta {
				bestDelta = vi.Delta
				bestValue = vi.Value
				bestScore = vi.Score
				bestSeverity = vi.Severity
			}
		}

		if bestValue != "" && bestValue != mi.CurrentVal {
			changes = append(changes, MetricChange{
				Metric:      mi.Metric,
				From:        mi.CurrentVal,
				To:          bestValue,
				Delta:       bestDelta,
				ResultScore: bestScore,
				Severity:    bestSeverity,
			})

			// 更新工作分数
			workingScore = bestScore
		}
	}

	return changes, nil
}

// MetricChange 表示一个指标变化
type MetricChange struct {
	Metric      string   // 指标短名称
	From        string   // 原值
	To          string   // 目标值
	Delta       float64  // 评分变化量
	ResultScore float64  // 变化后的评分
	Severity    Severity // 变化后的严重性
}

// String 返回变化的可读表示
func (mc MetricChange) String() string {
	return fmt.Sprintf("%s: %s → %s (Δ%.1f, result: %.1f %s)",
		mc.Metric, mc.From, mc.To, mc.Delta, mc.ResultScore, mc.Severity)
}

// SensitivityAnalysis 对所有指标进行敏感性分析
// 返回每个指标对评分的影响范围（最大升高和最大降低）
//
// 用法:
//
//	sensitivities := cvss.SensitivityAnalysis(cv)
//	for _, s := range sensitivities {
//	    fmt.Printf("%s: range %.1f to %.1f (swing: %.1f)\n",
//	        s.Metric, s.MinScore, s.MaxScore, s.ScoreSwing)
//	}
func SensitivityAnalysis(cv *Cvss3x) ([]MetricSensitivity, error) {
	if cv == nil {
		return nil, ErrNilReceiver
	}
	if err := cv.Check(); err != nil {
		return nil, err
	}

	calc := NewCalculator(cv)
	// 入口已 Check() 通过，基础评分计算不会失败
	baseScore, _ := calc.GetBaseScore()

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

	var sensitivities []MetricSensitivity

	for _, metric := range []string{"AV", "AC", "PR", "UI", "S", "C", "I", "A"} {
		var minScore, maxScore float64 = 10.0, 0.0

		for _, val := range metricValues[metric] {
			// metric 与 val 均来自合法枚举，modifyBaseMetric 与 GetBaseScore 不会失败
			modified, _ := modifyBaseMetric(cv, metric, val)
			modCalc := NewCalculator(modified)
			score, _ := modCalc.GetBaseScore()
			if score < minScore {
				minScore = score
			}
			if score > maxScore {
				maxScore = score
			}
		}

		sensitivities = append(sensitivities, MetricSensitivity{
			Metric:     metric,
			MinScore:   minScore,
			MaxScore:   maxScore,
			BaseScore:  baseScore,
			ScoreSwing: maxScore - minScore,
		})
	}

	// 按 swing 从大到小排序
	sort.Slice(sensitivities, func(i, j int) bool {
		return sensitivities[i].ScoreSwing > sensitivities[j].ScoreSwing
	})

	return sensitivities, nil
}

// MetricSensitivity 表示一个指标对评分的敏感度
type MetricSensitivity struct {
	Metric     string  // 指标短名称
	MinScore   float64 // 该指标所有值中的最低评分
	MaxScore   float64 // 该指标所有值中的最高评分
	BaseScore  float64 // 当前基础评分
	ScoreSwing float64 // MaxScore - MinScore，指标对评分的影响范围
}

// String 返回敏感度的可读表示
func (ms MetricSensitivity) String() string {
	return fmt.Sprintf("%s: %.1f ~ %.1f (swing: %.1f, current: %.1f)",
		ms.Metric, ms.MinScore, ms.MaxScore, ms.ScoreSwing, ms.BaseScore)
}

// modifyBaseMetric 创建一个修改了指定基础指标的副本
func modifyBaseMetric(cv *Cvss3x, metric string, val rune) (*Cvss3x, error) {
	result := cv.Clone()

	var v vector.Vector
	var err error

	switch metric {
	case "AV":
		v, err = vector.GetAttackVector(val)
		result.Cvss3xBase.AttackVector = v
	case "AC":
		v, err = vector.GetAttackComplexity(val)
		result.Cvss3xBase.AttackComplexity = v
	case "PR":
		v, err = vector.GetPrivilegesRequired(val)
		result.Cvss3xBase.PrivilegesRequired = v
	case "UI":
		v, err = vector.GetUserInteraction(val)
		result.Cvss3xBase.UserInteraction = v
	case "S":
		v, err = vector.GetScope(val)
		result.Cvss3xBase.Scope = v
	case "C":
		v, err = vector.GetConfidentiality(val)
		result.Cvss3xBase.Confidentiality = v
	case "I":
		v, err = vector.GetIntegrity(val)
		result.Cvss3xBase.Integrity = v
	case "A":
		v, err = vector.GetAvailability(val)
		result.Cvss3xBase.Availability = v
	default:
		return nil, fmt.Errorf("unknown metric: %s", metric)
	}

	if err != nil {
		return nil, err
	}

	return result, nil
}

// maxAbsDelta 返回 ValueImpact 切片中最大的绝对 delta
func maxAbsDelta(impacts []ValueImpact) float64 {
	if len(impacts) == 0 {
		return 0
	}
	max := 0.0
	for _, vi := range impacts {
		abs := math.Abs(vi.Delta)
		if abs > max {
			max = abs
		}
	}
	return max
}

// getValueLongNameMap 返回指标值到长名称的映射
func getValueLongNameMap() map[string]map[rune]string {
	return map[string]map[rune]string{
		"AV": {'N': "Network", 'A': "Adjacent", 'L': "Local", 'P': "Physical"},
		"AC": {'L': "Low", 'H': "High"},
		"PR": {'N': "None", 'L': "Low", 'H': "High"},
		"UI": {'N': "None", 'R': "Required"},
		"S":  {'U': "Unchanged", 'C': "Changed"},
		"C":  {'H': "High", 'L': "Low", 'N': "None"},
		"I":  {'H': "High", 'L': "Low", 'N': "None"},
		"A":  {'H': "High", 'L': "Low", 'N': "None"},
	}
}
