package parser

import (
	"strings"
	"testing"

	"github.com/scagogogo/cvss-skills/pkg/cvss"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// 本测试文件专门用于补齐 pkg/parser 包的覆盖率缺口，聚焦以下未覆盖分支：
//   - cvss3x_parser.go: Parse 的错误分支、readKey 空键、mapVectorToStruct 的
//     Temporal/Environmental 惰性初始化分支
//   - batch.go: workerCount 边界分支、非 ValidationErrors 的 parseErr 分支
//   - convenience.go: ParseAndValidate 解析失败分支、ParseAndScore 的成功/失败路径

// TestCvss3xParser_Parse_ErrorBranches 覆盖 Parse 中未覆盖的错误分支。
func TestCvss3xParser_Parse_ErrorBranches(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantErr    bool
		errContain string // 期望的错误信息子串
	}{
		{
			name:       "value without colon triggers readValue error",
			input:      "CVSS:3.1/AV",
			wantErr:    true,
			errContain: "expected ':' before value",
		},
		{
			name:       "trailing slash produces empty key",
			input:      "CVSS:3.1/AV:N/",
			wantErr:    true,
			errContain: "empty key",
		},
		{
			name:       "duplicate metric key",
			input:      "CVSS:3.1/AV:N/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			wantErr:    true,
			errContain: "appears more than once",
		},
		{
			name:       "version not followed by slash (ParseInt fails on trailing char)",
			input:      "CVSS:3.1X/AV:N",
			wantErr:    true,
			errContain: "invalid syntax",
		},
		{
			name:       "incomplete vector after version",
			input:      "CVSS:3.1",
			wantErr:    true,
			errContain: "incomplete vector string",
		},
		{
			name:       "unknown metric key",
			input:      "CVSS:3.1/ZZ:N/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			wantErr:    true,
			errContain: "unknown vector short name",
		},
		{
			name:       "invalid metric value",
			input:      "CVSS:3.1/AV:Q/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			wantErr:    true,
			errContain: "unknown attack vector value",
		},
		{
			// 键中含空格与 tab，readKey 会跳过这些空白（continue 分支），
			// 最终键仍为 "AV"，向量可正常解析。
			name:    "key with embedded whitespace is tolerated",
			input:   "CVSS:3.1/A V:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			wantErr: false,
		},
		{
			name:    "key with embedded tab is tolerated",
			input:   "CVSS:3.1/A\tV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseString(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errContain != "" {
					assert.True(t, strings.Contains(err.Error(), tt.errContain),
						"expected error containing %q, got %q", tt.errContain, err.Error())
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestCvss3xParser_Parse_DuplicateMetricErrIsSentinel 验证重复键错误包装了
// ErrDuplicateMetric 哨兵错误。
func TestCvss3xParser_Parse_DuplicateMetricErrIsSentinel(t *testing.T) {
	_, err := ParseString("CVSS:3.1/AV:N/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDuplicateMetric)
}

// TestCvss3xParser_mapVectorToStruct_TemporalInitEachMetric 覆盖每个 Temporal
// 指标（RL、RC）作为该组"第一个"指标时触发 nil-init true 分支。
// 注意 E 的 nil-init 已被现有测试覆盖，这里只需覆盖 RL、RC。
//
// 关键：每个指标必须是其所在组（Temporal）里第一个被映射的指标，才会进入
// `if nil { 初始化 }` 的 if 体。因此每个用例只包含单个 Temporal 指标。
func TestCvss3xParser_mapVectorToStruct_TemporalInitEachMetric(t *testing.T) {
	base := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	tests := []struct {
		name          string
		extraMetric   string
		checkTemporal func(*testing.T, *cvss.Cvss3xTemporal)
	}{
		{
			name:        "RL as first temporal metric",
			extraMetric: "/RL:O",
			checkTemporal: func(t *testing.T, tmp *cvss.Cvss3xTemporal) {
				assert.NotNil(t, tmp.RemediationLevel)
			},
		},
		{
			name:        "RC as first temporal metric",
			extraMetric: "/RC:C",
			checkTemporal: func(t *testing.T, tmp *cvss.Cvss3xTemporal) {
				assert.NotNil(t, tmp.ReportConfidence)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cv, err := ParseString(base + tt.extraMetric)
			require.NoError(t, err)
			require.NotNil(t, cv)
			require.NotNil(t, cv.Cvss3xTemporal, "Temporal 应被惰性初始化")
			tt.checkTemporal(t, cv.Cvss3xTemporal)
		})
	}
}

// TestCvss3xParser_mapVectorToStruct_EnvironmentalInitEachMetric 覆盖每个
// Environmental 指标作为该组"第一个"指标时触发 nil-init true 分支。
func TestCvss3xParser_mapVectorToStruct_EnvironmentalInitEachMetric(t *testing.T) {
	base := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	tests := []struct {
		name        string
		extraMetric string
		checkEnv    func(*testing.T, *cvss.Cvss3xEnvironmental)
	}{
		{"CR first", "/CR:H", func(t *testing.T, e *cvss.Cvss3xEnvironmental) { assert.NotNil(t, e.ConfidentialityRequirement) }},
		{"IR first", "/IR:H", func(t *testing.T, e *cvss.Cvss3xEnvironmental) { assert.NotNil(t, e.IntegrityRequirement) }},
		{"AR first", "/AR:H", func(t *testing.T, e *cvss.Cvss3xEnvironmental) { assert.NotNil(t, e.AvailabilityRequirement) }},
		{"MAV first", "/MAV:N", func(t *testing.T, e *cvss.Cvss3xEnvironmental) { assert.NotNil(t, e.ModifiedAttackVector) }},
		{"MAC first", "/MAC:L", func(t *testing.T, e *cvss.Cvss3xEnvironmental) { assert.NotNil(t, e.ModifiedAttackComplexity) }},
		{"MPR first", "/MPR:N", func(t *testing.T, e *cvss.Cvss3xEnvironmental) { assert.NotNil(t, e.ModifiedPrivilegesRequired) }},
		{"MUI first", "/MUI:N", func(t *testing.T, e *cvss.Cvss3xEnvironmental) { assert.NotNil(t, e.ModifiedUserInteraction) }},
		{"MS first", "/MS:U", func(t *testing.T, e *cvss.Cvss3xEnvironmental) { assert.NotNil(t, e.ModifiedScope) }},
		{"MC first", "/MC:N", func(t *testing.T, e *cvss.Cvss3xEnvironmental) { assert.NotNil(t, e.ModifiedConfidentiality) }},
		{"MI first", "/MI:N", func(t *testing.T, e *cvss.Cvss3xEnvironmental) { assert.NotNil(t, e.ModifiedIntegrity) }},
		{"MA first", "/MA:N", func(t *testing.T, e *cvss.Cvss3xEnvironmental) { assert.NotNil(t, e.ModifiedAvailability) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cv, err := ParseString(base + tt.extraMetric)
			require.NoError(t, err)
			require.NotNil(t, cv)
			require.NotNil(t, cv.Cvss3xEnvironmental, "Environmental 应被惰性初始化")
			tt.checkEnv(t, cv.Cvss3xEnvironmental)
		})
	}
}

// TestCvss3xParser_mapVectorToStruct_TemporalAlreadyInitialized 验证当
// Cvss3xTemporal 已被前一个指标初始化后，再次映射同组指标时不会重复初始化
// （覆盖 if nil 的 false 分支，即已存在的情况）。
func TestCvss3xParser_mapVectorToStruct_TemporalAlreadyInitialized(t *testing.T) {
	// E 先初始化 Temporal，RL/RC 命中已初始化分支
	vector := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:H/RL:O/RC:C"
	cv, err := ParseString(vector)
	require.NoError(t, err)
	require.NotNil(t, cv)
	require.NotNil(t, cv.Cvss3xTemporal)
	// 三个指标都应被正确赋值（证明已初始化分支也正常工作）
	assert.NotNil(t, cv.Cvss3xTemporal.ExploitCodeMaturity)
	assert.NotNil(t, cv.Cvss3xTemporal.RemediationLevel)
	assert.NotNil(t, cv.Cvss3xTemporal.ReportConfidence)
}

// TestCvss3xParser_mapVectorToStruct_EnvironmentalAlreadyInitialized 验证
// Environmental 已被前一个指标初始化后，后续指标命中已初始化分支。
func TestCvss3xParser_mapVectorToStruct_EnvironmentalAlreadyInitialized(t *testing.T) {
	// CR 先初始化 Environmental，其余 M* 指标命中已初始化分支
	vector := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" +
		"/CR:H/IR:H/AR:H/MAV:N"
	cv, err := ParseString(vector)
	require.NoError(t, err)
	require.NotNil(t, cv)
	require.NotNil(t, cv.Cvss3xEnvironmental)
	assert.NotNil(t, cv.Cvss3xEnvironmental.ConfidentialityRequirement)
	assert.NotNil(t, cv.Cvss3xEnvironmental.IntegrityRequirement)
	assert.NotNil(t, cv.Cvss3xEnvironmental.AvailabilityRequirement)
	assert.NotNil(t, cv.Cvss3xEnvironmental.ModifiedAttackVector)
}

// TestBatchParse_WorkerCountBoundaries 覆盖 BatchParse 中 workerCount<=0
// 与 workerCount>len(vectors) 两个分支。
func TestBatchParse_WorkerCountBoundaries(t *testing.T) {
	vectors := []string{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		"CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:C/C:L/I:L/A:N",
	}

	// workerCount <= 0 -> 使用 len(vectors)
	t.Run("workerCount zero", func(t *testing.T) {
		results := BatchParse(vectors, 0)
		require.Len(t, results, 2)
		assert.NoError(t, results[0].Error)
		assert.NoError(t, results[1].Error)
	})

	t.Run("workerCount negative", func(t *testing.T) {
		results := BatchParse(vectors, -5)
		require.Len(t, results, 2)
		assert.NoError(t, results[0].Error)
	})

	// workerCount > len(vectors) -> 截断为 len(vectors)
	t.Run("workerCount exceeds length", func(t *testing.T) {
		results := BatchParse(vectors, 100)
		require.Len(t, results, 2)
		assert.NoError(t, results[0].Error)
		assert.NoError(t, results[1].Error)
	})
}

// TestBatchValidate_WorkerCountBoundaries 覆盖 BatchValidate 中 workerCount<=0
// 与 workerCount>len(vectors) 两个分支。
func TestBatchValidate_WorkerCountBoundaries(t *testing.T) {
	vectors := []string{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		"CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:C/C:L/I:L/A:N",
	}

	t.Run("workerCount zero", func(t *testing.T) {
		results := BatchValidate(vectors, 0)
		require.Len(t, results, 2)
		assert.True(t, results[0].Valid)
		assert.True(t, results[1].Valid)
	})

	t.Run("workerCount exceeds length", func(t *testing.T) {
		results := BatchValidate(vectors, 100)
		require.Len(t, results, 2)
		assert.True(t, results[0].Valid)
		assert.True(t, results[1].Valid)
	})
}

// TestBatchValidate_ParseErrorNotValidationErrors 覆盖 BatchValidate 中
// parseErr 不是 cvss.ValidationErrors 的 else 分支（即解析阶段的错误，
// 而非验证阶段的错误）。
func TestBatchValidate_ParseErrorNotValidationErrors(t *testing.T) {
	// "INVALID" 会触发解析错误（魔术头不合法），返回普通 error 而非 ValidationErrors
	vectors := []string{
		"INVALID",
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
	}
	results := BatchValidate(vectors, 2)
	require.Len(t, results, 2)

	// index 0: 解析失败，走 else 分支，Errors 仅含错误字符串
	require.Error(t, results[0].Error)
	assert.False(t, results[0].Valid)
	require.Len(t, results[0].Errors, 1)
	// 确认不是 ValidationErrors 类型（即走 else 分支）
	_, isVE := results[0].Error.(cvss.ValidationErrors)
	assert.False(t, isVE, "解析错误不应是 ValidationErrors 类型")
	assert.Equal(t, results[0].Error.Error(), results[0].Errors[0])

	// index 1: 正常
	assert.True(t, results[1].Valid)
	assert.NoError(t, results[1].Error)
}

// TestBatchValidate_ValidationErrorsType 覆盖 BatchValidate 中
// parseErr 是 cvss.ValidationErrors 的分支（即解析成功但验证失败）。
func TestBatchValidate_ValidationErrorsType(t *testing.T) {
	// 缺少必需指标 -> 解析成功但 Validate 返回 ValidationErrors
	vectors := []string{
		"CVSS:3.1/AV:N",
	}
	results := BatchValidate(vectors, 1)
	require.Len(t, results, 1)
	require.Error(t, results[0].Error)
	assert.False(t, results[0].Valid)
	// 应为 ValidationErrors 类型，走 if 分支逐个提取
	ve, ok := results[0].Error.(cvss.ValidationErrors)
	require.True(t, ok, "验证错误应为 ValidationErrors 类型")
	assert.NotEmpty(t, ve)
	assert.Len(t, results[0].Errors, len(ve))
}

// TestParseAndValidate_ParseError 覆盖 ParseAndValidate 中 ParseString 失败分支。
func TestParseAndValidate_ParseError(t *testing.T) {
	cv, err := ParseAndValidate("INVALID")
	require.Error(t, err)
	assert.Nil(t, cv)
}

// TestParseAndValidate_Success 覆盖 ParseAndValidate 的成功路径。
func TestParseAndValidate_Success(t *testing.T) {
	cv, err := ParseAndValidate("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	require.NoError(t, err)
	require.NotNil(t, cv)
}

// TestParseAndScore_Success 覆盖 ParseAndScore 的成功路径（解析+评分+严重性）。
func TestParseAndScore_Success(t *testing.T) {
	cv, score, severity, err := ParseAndScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	require.NoError(t, err)
	require.NotNil(t, cv)
	assert.InDelta(t, 9.8, score, 0.1)
	assert.Equal(t, cvss.SeverityCritical, severity)
}

// TestParseAndScore_ParseError 覆盖 ParseAndScore 中 ParseString 失败分支。
func TestParseAndScore_ParseError(t *testing.T) {
	cv, score, severity, err := ParseAndScore("INVALID")
	require.Error(t, err)
	assert.Nil(t, cv)
	assert.Equal(t, float64(0), score)
	assert.Equal(t, cvss.SeverityNone, severity)
}

// TestParseAndScore_CalculateError 覆盖 ParseAndScore 中 Calculate 失败分支。
// 解析成功但向量不完整（缺少必需的 Base 指标），Check/Calculate 会返回错误。
func TestParseAndScore_CalculateError(t *testing.T) {
	// 解析成功（AV:N 合法），但缺少其余必需指标 -> Calculate 内部 Check 失败
	cv, score, severity, err := ParseAndScore("CVSS:3.1/AV:N")
	require.Error(t, err)
	// ParseAndScore 在 Calculate 失败时返回解析得到的 cv（非 nil）
	assert.NotNil(t, cv)
	assert.Equal(t, float64(0), score)
	assert.Equal(t, cvss.SeverityNone, severity)
}
