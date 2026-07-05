package cvss

import (
	"math"

	"github.com/scagogogo/cvss-skills/pkg/vector"
)

// isEnvironmentalMetricsComplete 检查两个向量的环境指标是否完整
func (dc *DistanceCalculator) isEnvironmentalMetricsComplete() bool {
	if dc.vector1 == nil || dc.vector2 == nil ||
		dc.vector1.Cvss3xEnvironmental == nil || dc.vector2.Cvss3xEnvironmental == nil {
		return false
	}

	e1 := dc.vector1.Cvss3xEnvironmental
	e2 := dc.vector2.Cvss3xEnvironmental

	// 至少要有一些环境指标被设置
	hasE1 := e1.ConfidentialityRequirement != nil || e1.IntegrityRequirement != nil ||
		e1.AvailabilityRequirement != nil || e1.ModifiedAttackVector != nil ||
		e1.ModifiedAttackComplexity != nil || e1.ModifiedPrivilegesRequired != nil ||
		e1.ModifiedUserInteraction != nil || e1.ModifiedScope != nil ||
		e1.ModifiedConfidentiality != nil || e1.ModifiedIntegrity != nil ||
		e1.ModifiedAvailability != nil

	hasE2 := e2.ConfidentialityRequirement != nil || e2.IntegrityRequirement != nil ||
		e2.AvailabilityRequirement != nil || e2.ModifiedAttackVector != nil ||
		e2.ModifiedAttackComplexity != nil || e2.ModifiedPrivilegesRequired != nil ||
		e2.ModifiedUserInteraction != nil || e2.ModifiedScope != nil ||
		e2.ModifiedConfidentiality != nil || e2.ModifiedIntegrity != nil ||
		e2.ModifiedAvailability != nil

	return hasE1 && hasE2
}

// getEnvironmentalScoreDiffs 计算两个向量环境指标之间的分数差异
// 返回每个维度的分数差异
func (dc *DistanceCalculator) getEnvironmentalScoreDiffs() []float64 {
	e1 := dc.vector1.Cvss3xEnvironmental
	e2 := dc.vector2.Cvss3xEnvironmental

	diffs := make([]float64, 0, 11)

	// CR, IR, AR — 使用分数差异
	diffs = append(diffs, envScoreDiff(e1.ConfidentialityRequirement, e2.ConfidentialityRequirement))
	diffs = append(diffs, envScoreDiff(e1.IntegrityRequirement, e2.IntegrityRequirement))
	diffs = append(diffs, envScoreDiff(e1.AvailabilityRequirement, e2.AvailabilityRequirement))

	// MAV, MAC, MPR, MUI — 使用分数差异
	diffs = append(diffs, envScoreDiff(e1.ModifiedAttackVector, e2.ModifiedAttackVector))
	diffs = append(diffs, envScoreDiff(e1.ModifiedAttackComplexity, e2.ModifiedAttackComplexity))

	// MPR needs scope context
	diffs = append(diffs, envPRScoreDiff(e1.ModifiedPrivilegesRequired, e2.ModifiedPrivilegesRequired,
		dc.vector1.Cvss3xEnvironmental.ModifiedScope, dc.vector1.Cvss3xBase.Scope,
		dc.vector2.Cvss3xEnvironmental.ModifiedScope, dc.vector2.Cvss3xBase.Scope))

	// MUI needs version context (v3.0 UI:R=0.56, v3.1 UI:R=0.62)
	diffs = append(diffs, envUIScoreDiff(e1.ModifiedUserInteraction, e2.ModifiedUserInteraction,
		dc.vector1.MinorVersion, dc.vector2.MinorVersion))

	// MS — binary 0/1
	scopeDiff := 0.0
	if envShortValue(e1.ModifiedScope, e2.ModifiedScope) {
		scopeDiff = 1.0
	}
	diffs = append(diffs, scopeDiff)

	// MC, MI, MA
	diffs = append(diffs, envScoreDiff(e1.ModifiedConfidentiality, e2.ModifiedConfidentiality))
	diffs = append(diffs, envScoreDiff(e1.ModifiedIntegrity, e2.ModifiedIntegrity))
	diffs = append(diffs, envScoreDiff(e1.ModifiedAvailability, e2.ModifiedAvailability))

	return diffs
}

// EuclideanDistanceWithEnv 计算包含环境指标的欧几里得距离
func (dc *DistanceCalculator) EuclideanDistanceWithEnv() float64 {
	if !dc.isBaseMetricsComplete() {
		return 0.0
	}

	sum := 0.0
	for _, diff := range dc.getBaseScoreDiffs() {
		sum += math.Pow(diff, 2)
	}

	temporalDiffs := dc.getTemporalScoreDiffs()
	if temporalDiffs != nil {
		for _, diff := range temporalDiffs {
			sum += math.Pow(diff, 2)
		}
	}

	if dc.isEnvironmentalMetricsComplete() {
		for _, diff := range dc.getEnvironmentalScoreDiffs() {
			sum += math.Pow(diff, 2)
		}
	}

	if sum > 0 {
		return math.Sqrt(sum)
	}
	return 0.0
}

// ManhattanDistanceWithEnv 计算包含环境指标的曼哈顿距离
func (dc *DistanceCalculator) ManhattanDistanceWithEnv() float64 {
	if !dc.isBaseMetricsComplete() {
		return 0.0
	}

	sum := 0.0
	for _, diff := range dc.getBaseScoreDiffs() {
		sum += diff
	}

	temporalDiffs := dc.getTemporalScoreDiffs()
	if temporalDiffs != nil {
		for _, diff := range temporalDiffs {
			sum += diff
		}
	}

	if dc.isEnvironmentalMetricsComplete() {
		for _, diff := range dc.getEnvironmentalScoreDiffs() {
			sum += diff
		}
	}

	return sum
}

// HammingDistanceWithEnv 计算包含环境指标的汉明距离
func (dc *DistanceCalculator) HammingDistanceWithEnv() int {
	diff := dc.HammingDistance()

	if dc.vector1.Cvss3xEnvironmental == nil || dc.vector2.Cvss3xEnvironmental == nil {
		return diff
	}

	e1 := dc.vector1.Cvss3xEnvironmental
	e2 := dc.vector2.Cvss3xEnvironmental

	// Compare environmental metrics
	if e1.ConfidentialityRequirement != nil && e2.ConfidentialityRequirement != nil &&
		e1.ConfidentialityRequirement.GetShortValue() != e2.ConfidentialityRequirement.GetShortValue() {
		diff++
	}
	if e1.IntegrityRequirement != nil && e2.IntegrityRequirement != nil &&
		e1.IntegrityRequirement.GetShortValue() != e2.IntegrityRequirement.GetShortValue() {
		diff++
	}
	if e1.AvailabilityRequirement != nil && e2.AvailabilityRequirement != nil &&
		e1.AvailabilityRequirement.GetShortValue() != e2.AvailabilityRequirement.GetShortValue() {
		diff++
	}
	if e1.ModifiedAttackVector != nil && e2.ModifiedAttackVector != nil &&
		e1.ModifiedAttackVector.GetShortValue() != e2.ModifiedAttackVector.GetShortValue() {
		diff++
	}
	if e1.ModifiedAttackComplexity != nil && e2.ModifiedAttackComplexity != nil &&
		e1.ModifiedAttackComplexity.GetShortValue() != e2.ModifiedAttackComplexity.GetShortValue() {
		diff++
	}
	if e1.ModifiedPrivilegesRequired != nil && e2.ModifiedPrivilegesRequired != nil &&
		e1.ModifiedPrivilegesRequired.GetShortValue() != e2.ModifiedPrivilegesRequired.GetShortValue() {
		diff++
	}
	if e1.ModifiedUserInteraction != nil && e2.ModifiedUserInteraction != nil &&
		e1.ModifiedUserInteraction.GetShortValue() != e2.ModifiedUserInteraction.GetShortValue() {
		diff++
	}
	if e1.ModifiedScope != nil && e2.ModifiedScope != nil &&
		e1.ModifiedScope.GetShortValue() != e2.ModifiedScope.GetShortValue() {
		diff++
	}
	if e1.ModifiedConfidentiality != nil && e2.ModifiedConfidentiality != nil &&
		e1.ModifiedConfidentiality.GetShortValue() != e2.ModifiedConfidentiality.GetShortValue() {
		diff++
	}
	if e1.ModifiedIntegrity != nil && e2.ModifiedIntegrity != nil &&
		e1.ModifiedIntegrity.GetShortValue() != e2.ModifiedIntegrity.GetShortValue() {
		diff++
	}
	if e1.ModifiedAvailability != nil && e2.ModifiedAvailability != nil &&
		e1.ModifiedAvailability.GetShortValue() != e2.ModifiedAvailability.GetShortValue() {
		diff++
	}

	return diff
}

// envScoreDiff 计算两个环境指标向量之间的分数差异
func envScoreDiff(v1, v2 vector.Vector) float64 {
	if v1 == nil || v2 == nil {
		return 0.0
	}
	return math.Abs(v1.GetScore() - v2.GetScore())
}

// envPRScoreDiff 计算两个 ModifiedPrivilegesRequired 之间的分数差异
func envPRScoreDiff(mpr1, mpr2, ms1, s1, ms2, s2 vector.Vector) float64 {
	if mpr1 == nil || mpr2 == nil {
		return 0.0
	}
	scope1Changed := vector.IsModifiedScopeChanged(ms1, s1)
	scope2Changed := vector.IsModifiedScopeChanged(ms2, s2)
	pr1Score := vector.GetPrivilegesRequiredScore(mpr1, scope1Changed)
	pr2Score := vector.GetPrivilegesRequiredScore(mpr2, scope2Changed)
	return math.Abs(pr1Score - pr2Score)
}

// envShortValue 比较两个环境指标向量的短值是否不同
func envShortValue(v1, v2 vector.Vector) bool {
	if v1 == nil || v2 == nil {
		return false
	}
	return v1.GetShortValue() != v2.GetShortValue()
}

// envUIScoreDiff 计算两个 ModifiedUserInteraction 之间的分数差异
// 需要版本信息，因为 v3.0 UI:R=0.56 而 v3.1 UI:R=0.62
func envUIScoreDiff(mui1, mui2 vector.Vector, minorV1, minorV2 int) float64 {
	if mui1 == nil || mui2 == nil {
		return 0.0
	}
	ui1 := vector.GetUserInteractionScore(mui1, minorV1)
	ui2 := vector.GetUserInteractionScore(mui2, minorV2)
	return math.Abs(ui1 - ui2)
}

// JaccardSimilarityWithEnv 计算包含环境指标的 Jaccard 相似度
// 相同指标数量除以总指标数量（包括基础、时间和环境指标）
func (dc *DistanceCalculator) JaccardSimilarityWithEnv() float64 {
	if dc.vector1 == nil || dc.vector2 == nil ||
		dc.vector1.Cvss3xBase == nil || dc.vector2.Cvss3xBase == nil {
		return 0.0
	}

	// 计算总指标数
	totalMetrics := 8 // 基础指标

	// 时间指标
	if dc.vector1.Cvss3xTemporal != nil && dc.vector2.Cvss3xTemporal != nil &&
		dc.vector1.Cvss3xTemporal.ExploitCodeMaturity != nil && dc.vector2.Cvss3xTemporal.ExploitCodeMaturity != nil &&
		dc.vector1.Cvss3xTemporal.RemediationLevel != nil && dc.vector2.Cvss3xTemporal.RemediationLevel != nil &&
		dc.vector1.Cvss3xTemporal.ReportConfidence != nil && dc.vector2.Cvss3xTemporal.ReportConfidence != nil {
		totalMetrics += 3
	}

	// 环境指标
	if dc.isEnvironmentalMetricsComplete() {
		totalMetrics += 11 // CR, IR, AR, MAV, MAC, MPR, MUI, MS, MC, MI, MA
	}

	// 计算汉明距离（包含环境）
	hammingDist := dc.HammingDistanceWithEnv()

	// Jaccard 相似度 = 相同指标数 / 总指标数
	// totalMetrics 至少为 8（基础指标恒计入），不会为 0。
	sameMetrics := totalMetrics - hammingDist
	return float64(sameMetrics) / float64(totalMetrics)
}
