package mock

import (
	"testing"

	"github.com/scagogogo/cvss-skills/pkg/cvss"
	"github.com/scagogogo/cvss-skills/pkg/vector"
	"github.com/stretchr/testify/assert"
)

// TestRandomCvss3x_Versions 验证各 minorVersion 入参的版本分支,
// 其中非 0/1 的入参会被规范化为 1(覆盖 RandomCvss3x 的默认分支)。
func TestRandomCvss3x_Versions(t *testing.T) {
	testCases := []struct {
		name           string
		minorVersion   int
		expectedMinor  int
		expectedPrefix string
	}{
		{"3.0", 0, 0, "CVSS:3.0"},
		{"3.1", 1, 1, "CVSS:3.1"},
		{"invalid 2 normalized to 3.1", 2, 1, "CVSS:3.1"},
		{"invalid -1 normalized to 3.1", -1, 1, "CVSS:3.1"},
		{"invalid 99 normalized to 3.1", 99, 1, "CVSS:3.1"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cv := RandomCvss3x(tc.minorVersion)
			assert.NotNil(t, cv)
			assert.Equal(t, 3, cv.MajorVersion)
			assert.Equal(t, tc.expectedMinor, cv.MinorVersion)
			assert.NotNil(t, cv.Cvss3xBase)
			assert.Equal(t, tc.expectedPrefix, cv.String()[:8])
		})
	}
}

// TestRandomCvss3x_Legality 多次随机生成,验证:
//   - 8 个基础指标全部已设置(非 nil)
//   - 生成的向量通过 Check() 校验
//   - 评分计算成功且落在 [0, 10]
func TestRandomCvss3x_Legality(t *testing.T) {
	for i := 0; i < 500; i++ {
		for _, mv := range []int{0, 1} {
			cv := RandomCvss3x(mv)
			assert.NotNil(t, cv.Cvss3xBase)

			// 8 个基础指标必须全部已设置
			assert.NotNil(t, cv.Cvss3xBase.AttackVector, "AttackVector must be set")
			assert.NotNil(t, cv.Cvss3xBase.AttackComplexity, "AttackComplexity must be set")
			assert.NotNil(t, cv.Cvss3xBase.PrivilegesRequired, "PrivilegesRequired must be set")
			assert.NotNil(t, cv.Cvss3xBase.UserInteraction, "UserInteraction must be set")
			assert.NotNil(t, cv.Cvss3xBase.Scope, "Scope must be set")
			assert.NotNil(t, cv.Cvss3xBase.Confidentiality, "Confidentiality must be set")
			assert.NotNil(t, cv.Cvss3xBase.Integrity, "Integrity must be set")
			assert.NotNil(t, cv.Cvss3xBase.Availability, "Availability must be set")

			// 合法性校验
			assert.NoError(t, cv.Check(), "vector must be legal: %s", cv.String())

			// 评分计算成功
			calc := cvss.NewCalculator(cv)
			score, err := calc.Calculate()
			assert.NoError(t, err, "calculate must succeed: %s", cv.String())
			assert.GreaterOrEqual(t, score, 0.0)
			assert.LessOrEqual(t, score, 10.0)
		}
	}
}

// TestRandomCvss3x_Distribution 验证随机生成确实覆盖到每个指标的全部取值,
// 确保不是固定返回同一个值(回归保护,避免未来改动把 randomFromSlice 改成取首元素)。
func TestRandomCvss3x_Distribution(t *testing.T) {
	seenAV := map[vector.Vector]bool{}
	seenS := map[vector.Vector]bool{}
	seenC := map[vector.Vector]bool{}

	for i := 0; i < 2000; i++ {
		cv := RandomCvss3x(1)
		seenAV[cv.Cvss3xBase.AttackVector] = true
		seenS[cv.Cvss3xBase.Scope] = true
		seenC[cv.Cvss3xBase.Confidentiality] = true
	}

	assert.Len(t, seenAV, 4, "AttackVector should hit all 4 values")
	assert.Len(t, seenS, 2, "Scope should hit both values")
	assert.Len(t, seenC, 3, "Confidentiality should hit all 3 values")
}

// TestRandomCvss3xWithScore_Versions 验证各版本下评分计算的成功路径。
func TestRandomCvss3xWithScore_Versions(t *testing.T) {
	testCases := []struct {
		name         string
		minorVersion int
	}{
		{"3.0", 0},
		{"3.1", 1},
		{"invalid normalized to 3.1", 2},
		{"invalid negative normalized to 3.1", -5},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cv, score, err := RandomCvss3xWithScore(tc.minorVersion)
			assert.NoError(t, err)
			assert.NotNil(t, cv)
			assert.GreaterOrEqual(t, score, 0.0)
			assert.LessOrEqual(t, score, 10.0)
			assert.Equal(t, 3, cv.MajorVersion)
		})
	}
}

// TestRandomCvss3xWithScore_SuccessPath 验证成功路径返回的对象与独立计算一致。
func TestRandomCvss3xWithScore_SuccessPath(t *testing.T) {
	cv, score, err := RandomCvss3xWithScore(1)
	assert.NoError(t, err)
	assert.NotNil(t, cv)

	// 与独立计算结果一致
	calc := cvss.NewCalculator(cv)
	expected, err := calc.Calculate()
	assert.NoError(t, err)
	assert.Equal(t, expected, score)
}

// ==================== CVSS 3.0 Presets ====================

// TestCriticalCvss30 验证 3.0 Critical 预设:版本 3.0、向量内容、分数 10.0。
func TestCriticalCvss30(t *testing.T) {
	cv := CriticalCvss30()
	assert.NotNil(t, cv)
	assert.Equal(t, 3, cv.MajorVersion)
	assert.Equal(t, 0, cv.MinorVersion)
	assert.NotNil(t, cv.Cvss3xBase)
	assert.Equal(t, "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", cv.String())

	calc := cvss.NewCalculator(cv)
	score, err := calc.Calculate()
	assert.NoError(t, err)
	assert.Equal(t, 10.0, score)
	assert.NoError(t, cv.Check())
}

// TestHighCvss30 验证 3.0 High 预设:版本 3.0、向量内容、分数 9.8(High 档位)。
func TestHighCvss30(t *testing.T) {
	cv := HighCvss30()
	assert.NotNil(t, cv)
	assert.Equal(t, 3, cv.MajorVersion)
	assert.Equal(t, 0, cv.MinorVersion)
	assert.NotNil(t, cv.Cvss3xBase)
	assert.Equal(t, "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", cv.String())

	calc := cvss.NewCalculator(cv)
	score, err := calc.Calculate()
	assert.NoError(t, err)
	assert.InDelta(t, 9.8, score, 0.01)
	assert.NoError(t, cv.Check())
}

// TestMediumCvss30 验证 3.0 Medium 预设:版本 3.0、向量内容、分数落在 Medium 档位。
func TestMediumCvss30(t *testing.T) {
	cv := MediumCvss30()
	assert.NotNil(t, cv)
	assert.Equal(t, 3, cv.MajorVersion)
	assert.Equal(t, 0, cv.MinorVersion)
	assert.NotNil(t, cv.Cvss3xBase)
	assert.Equal(t, "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", cv.String())

	calc := cvss.NewCalculator(cv)
	score, err := calc.Calculate()
	assert.NoError(t, err)
	// Medium 档位 4.0 - 6.9
	assert.GreaterOrEqual(t, score, 4.0)
	assert.LessOrEqual(t, score, 6.9)
	assert.NoError(t, cv.Check())
}

// TestLowCvss30 验证 3.0 Low 预设:版本 3.0、向量内容、分数落在 Low 档位。
func TestLowCvss30(t *testing.T) {
	cv := LowCvss30()
	assert.NotNil(t, cv)
	assert.Equal(t, 3, cv.MajorVersion)
	assert.Equal(t, 0, cv.MinorVersion)
	assert.NotNil(t, cv.Cvss3xBase)
	assert.Equal(t, "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", cv.String())

	calc := cvss.NewCalculator(cv)
	score, err := calc.Calculate()
	assert.NoError(t, err)
	// Low 档位 0.1 - 3.9
	assert.GreaterOrEqual(t, score, 0.1)
	assert.LessOrEqual(t, score, 3.9)
	assert.NoError(t, cv.Check())
}

// TestNoneCvss30 验证 3.0 None 预设:版本 3.0、向量内容、分数 0.0。
func TestNoneCvss30(t *testing.T) {
	cv := NoneCvss30()
	assert.NotNil(t, cv)
	assert.Equal(t, 3, cv.MajorVersion)
	assert.Equal(t, 0, cv.MinorVersion)
	assert.NotNil(t, cv.Cvss3xBase)
	assert.Equal(t, "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", cv.String())

	calc := cvss.NewCalculator(cv)
	score, err := calc.Calculate()
	assert.NoError(t, err)
	assert.Equal(t, 0.0, score)
	assert.NoError(t, cv.Check())
}

// TestCvss30Presets_Severity 验证 3.0 各预设向量落在对应的严重性档位。
func TestCvss30Presets_Severity(t *testing.T) {
	testCases := []struct {
		name     string
		preset   func() *cvss.Cvss3x
		minScore float64
		maxScore float64
	}{
		{"Critical", CriticalCvss30, 9.0, 10.0},
		{"High", HighCvss30, 7.0, 10.0},
		{"Medium", MediumCvss30, 4.0, 6.9},
		{"Low", LowCvss30, 0.1, 3.9},
		{"None", NoneCvss30, 0.0, 0.0},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cv := tc.preset()
			assert.Equal(t, 3, cv.MajorVersion)
			assert.Equal(t, 0, cv.MinorVersion)
			calc := cvss.NewCalculator(cv)
			score, err := calc.Calculate()
			assert.NoError(t, err)
			assert.GreaterOrEqual(t, score, tc.minScore, "%s preset score should be >= %f", tc.name, tc.minScore)
			assert.LessOrEqual(t, score, tc.maxScore, "%s preset score should be <= %f", tc.name, tc.maxScore)
			assert.NoError(t, cv.Check())
		})
	}
}
