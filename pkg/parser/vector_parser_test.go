package parser

import (
	"testing"

	"github.com/scagogogo/cvss-parser/pkg/vector"
	"github.com/stretchr/testify/assert"
)

// TestVectorParser_Parse 测试向量解析器的Parse方法
func TestVectorParser_Parse(t *testing.T) {
	testCases := []struct {
		name        string
		vectorName  string
		vectorValue rune
		wantErr     bool
		expected    vector.Vector
	}{
		{
			name:        "Valid AttackVector Network",
			vectorName:  "AV",
			vectorValue: 'N',
			wantErr:     false,
			expected:    vector.AttackVectorNetwork,
		},
		{
			name:        "Valid AttackVector Adjacent",
			vectorName:  "AV",
			vectorValue: 'A',
			wantErr:     false,
			expected:    vector.AttackVectorAdjacent,
		},
		{
			name:        "Valid AttackComplexity Low",
			vectorName:  "AC",
			vectorValue: 'L',
			wantErr:     false,
			expected:    vector.AttackComplexityLow,
		},
		{
			name:        "Valid Scope Changed",
			vectorName:  "S",
			vectorValue: 'C',
			wantErr:     false,
			expected:    vector.ScopeChanged,
		},
		{
			name:        "Valid Temporal Vector",
			vectorName:  "E",
			vectorValue: 'H',
			wantErr:     false,
			expected:    vector.ExploitCodeMaturityHigh,
		},
		{
			name:        "Valid Environmental Vector",
			vectorName:  "CR",
			vectorValue: 'H',
			wantErr:     false,
			expected:    vector.ConfidentialityRequirementHigh,
		},
		{
			name:        "Invalid Vector Name",
			vectorName:  "XX",
			vectorValue: 'N',
			wantErr:     true,
			expected:    nil,
		},
		{
			name:        "Invalid Vector Value",
			vectorName:  "AV",
			vectorValue: 'X',
			wantErr:     true,
			expected:    nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := DefaultVectorParser.Parse(tc.vectorName, tc.vectorValue)

			if tc.wantErr {
				assert.Error(t, err)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}

// TestVectorParser_Add 测试向量解析器的Add方法
func TestVectorParser_Add(t *testing.T) {
	// 创建一个新的VectorParser
	parser := &VectorParser{
		VectorMap: make(map[string]map[rune]vector.Vector),
	}

	// 测试添加向量
	testVectors := []vector.Vector{
		vector.AttackVectorNetwork,
		vector.AttackComplexityLow,
		vector.PrivilegesRequiredNone,
		vector.UserInteractionNone,
	}

	for _, v := range testVectors {
		parser.Add(v)
	}

	// 验证向量添加后能被解析
	for _, v := range testVectors {
		shortName := v.GetShortName()
		shortValue := v.GetShortValue()

		// 测试解析
		result, err := parser.Parse(shortName, shortValue)
		assert.NoError(t, err)
		assert.Equal(t, v, result)
	}
}

// TestVectorParser_ParseInvalidInput 测试向量解析器解析无效输入
func TestVectorParser_ParseInvalidInput(t *testing.T) {
	// 测试向量名不存在的情况
	v, err := DefaultVectorParser.Parse("NonExistentVector", 'N')
	assert.Error(t, err)
	assert.Nil(t, v)
	assert.Contains(t, err.Error(), "does not exist")

	// 测试向量值不存在的情况
	v, err = DefaultVectorParser.Parse("AV", 'Z')
	assert.Error(t, err)
	assert.Nil(t, v)
	assert.Contains(t, err.Error(), "does not exist")
}

// TestVectorParser_Complete 测试向量解析器的完整性
func TestVectorParser_Complete(t *testing.T) {
	// 验证DefaultVectorParser包含所有支持的向量类型
	vectorTypes := []struct {
		name       string
		shortName  string
		shortValue rune
	}{
		{"AttackVectorNetwork", "AV", 'N'},
		{"AttackVectorAdjacent", "AV", 'A'},
		{"AttackVectorLocal", "AV", 'L'},
		{"AttackVectorPhysical", "AV", 'P'},

		{"AttackComplexityLow", "AC", 'L'},
		{"AttackComplexityHigh", "AC", 'H'},

		{"PrivilegesRequiredNone", "PR", 'N'},
		{"PrivilegesRequiredLow", "PR", 'L'},
		{"PrivilegesRequiredHigh", "PR", 'H'},

		{"UserInteractionNone", "UI", 'N'},
		{"UserInteractionRequired", "UI", 'R'},

		{"ScopeUnchanged", "S", 'U'},
		{"ScopeChanged", "S", 'C'},

		{"ConfidentialityNone", "C", 'N'},
		{"ConfidentialityLow", "C", 'L'},
		{"ConfidentialityHigh", "C", 'H'},

		{"IntegrityNone", "I", 'N'},
		{"IntegrityLow", "I", 'L'},
		{"IntegrityHigh", "I", 'H'},

		{"AvailabilityNone", "A", 'N'},
		{"AvailabilityLow", "A", 'L'},
		{"AvailabilityHigh", "A", 'H'},

		// 时间指标
		{"ExploitCodeMaturityNotDefined", "E", 'X'},
		{"ExploitCodeMaturityUnproven", "E", 'U'},
		{"ExploitCodeMaturityProofOfConcept", "E", 'P'},
		{"ExploitCodeMaturityFunctional", "E", 'F'},
		{"ExploitCodeMaturityHigh", "E", 'H'},

		{"RemediationLevelNotDefined", "RL", 'X'},
		{"RemediationLevelOfficialFix", "RL", 'O'},
		{"RemediationLevelTemporaryFix", "RL", 'T'},
		{"RemediationLevelWorkaround", "RL", 'W'},
		{"RemediationLevelUnavailable", "RL", 'U'},

		{"ReportConfidenceNotDefined", "RC", 'X'},
		{"ReportConfidenceUnknown", "RC", 'U'},
		{"ReportConfidenceReasonable", "RC", 'R'},
		{"ReportConfidenceConfirmed", "RC", 'C'},

		// 环境指标
		{"ConfidentialityRequirementNotDefined", "CR", 'X'},
		{"ConfidentialityRequirementLow", "CR", 'L'},
		{"ConfidentialityRequirementMedium", "CR", 'M'},
		{"ConfidentialityRequirementHigh", "CR", 'H'},
	}

	for _, vt := range vectorTypes {
		t.Run(vt.name, func(t *testing.T) {
			v, err := DefaultVectorParser.Parse(vt.shortName, vt.shortValue)
			assert.NoError(t, err)
			assert.NotNil(t, v)
			assert.Equal(t, vt.shortName, v.GetShortName())
			assert.Equal(t, vt.shortValue, v.GetShortValue())
		})
	}
}

// TestVectorParser_NewVectorParser 测试创建新的向量解析器
func TestVectorParser_NewVectorParser(t *testing.T) {
	parser := NewVectorParser()
	assert.NotNil(t, parser)
	assert.NotNil(t, parser.VectorMap)

	// 测试一个基本解析功能以确保初始化正确
	v, err := parser.Parse("AV", 'N')
	assert.NoError(t, err)
	assert.Equal(t, vector.AttackVectorNetwork, v)
}
