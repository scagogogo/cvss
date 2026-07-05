package vector

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestGetPrivilegesRequiredTable 测试获取所需权限（含全部合法值与非法值）
func TestGetPrivilegesRequiredTable(t *testing.T) {
	testCases := []struct {
		name     string
		value    rune
		wantErr  bool
		expected Vector
	}{
		{"None", 'N', false, PrivilegesRequiredNone},
		{"Low", 'L', false, PrivilegesRequiredLow},
		{"High", 'H', false, PrivilegesRequiredHigh},
		{"Invalid", 'Z', true, nil},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			v, err := GetPrivilegesRequired(tc.value)
			if tc.wantErr {
				assert.Error(t, err)
				assert.Nil(t, v)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, v)
			}
		})
	}
}

// TestGetUserInteractionTable 测试获取用户交互（含全部合法值与非法值）
func TestGetUserInteractionTable(t *testing.T) {
	testCases := []struct {
		name     string
		value    rune
		wantErr  bool
		expected Vector
	}{
		{"None", 'N', false, UserInteractionNone},
		{"Required", 'R', false, UserInteractionRequired},
		{"Invalid", 'Z', true, nil},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			v, err := GetUserInteraction(tc.value)
			if tc.wantErr {
				assert.Error(t, err)
				assert.Nil(t, v)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, v)
			}
		})
	}
}

// TestGetScopeTable 测试获取范围（含全部合法值与非法值）
func TestGetScopeTable(t *testing.T) {
	testCases := []struct {
		name     string
		value    rune
		wantErr  bool
		expected Vector
	}{
		{"Unchanged", 'U', false, ScopeUnchanged},
		{"Changed", 'C', false, ScopeChanged},
		{"Invalid", 'Z', true, nil},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			v, err := GetScope(tc.value)
			if tc.wantErr {
				assert.Error(t, err)
				assert.Nil(t, v)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, v)
			}
		})
	}
}

// TestGetConfidentialityTable 测试获取机密性（含全部合法值与非法值）
func TestGetConfidentialityTable(t *testing.T) {
	testCases := []struct {
		name     string
		value    rune
		wantErr  bool
		expected Vector
	}{
		{"None", 'N', false, ConfidentialityNone},
		{"Low", 'L', false, ConfidentialityLow},
		{"High", 'H', false, ConfidentialityHigh},
		{"Invalid", 'Z', true, nil},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			v, err := GetConfidentiality(tc.value)
			if tc.wantErr {
				assert.Error(t, err)
				assert.Nil(t, v)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, v)
			}
		})
	}
}

// TestGetIntegrityTable 测试获取完整性（含全部合法值与非法值）
func TestGetIntegrityTable(t *testing.T) {
	testCases := []struct {
		name     string
		value    rune
		wantErr  bool
		expected Vector
	}{
		{"None", 'N', false, IntegrityNone},
		{"Low", 'L', false, IntegrityLow},
		{"High", 'H', false, IntegrityHigh},
		{"Invalid", 'Z', true, nil},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			v, err := GetIntegrity(tc.value)
			if tc.wantErr {
				assert.Error(t, err)
				assert.Nil(t, v)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, v)
			}
		})
	}
}

// TestGetAvailabilityTable 测试获取可用性（含全部合法值与非法值）
func TestGetAvailabilityTable(t *testing.T) {
	testCases := []struct {
		name     string
		value    rune
		wantErr  bool
		expected Vector
	}{
		{"None", 'N', false, AvailabilityNone},
		{"Low", 'L', false, AvailabilityLow},
		{"High", 'H', false, AvailabilityHigh},
		{"Invalid", 'Z', true, nil},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			v, err := GetAvailability(tc.value)
			if tc.wantErr {
				assert.Error(t, err)
				assert.Nil(t, v)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, v)
			}
		})
	}
}

// TestGetModifiedUserInteraction 测试获取修改后的用户交互
func TestGetModifiedUserInteraction(t *testing.T) {
	testCases := []struct {
		name     string
		value    rune
		wantErr  bool
		expected Vector
	}{
		{"NotDefined", 'X', false, UserInteractionNotDefined},
		{"None", 'N', false, ModifiedUserInteractionNone},
		{"Required", 'R', false, ModifiedUserInteractionRequired},
		{"Invalid", 'Z', true, nil},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			v, err := GetModifiedUserInteraction(tc.value)
			if tc.wantErr {
				assert.Error(t, err)
				assert.Nil(t, v)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, v)
			}
		})
	}
}

// TestGetModifiedScope 测试获取修改后的范围
func TestGetModifiedScope(t *testing.T) {
	testCases := []struct {
		name     string
		value    rune
		wantErr  bool
		expected Vector
	}{
		{"NotDefined", 'X', false, ScopeNotDefined},
		{"Unchanged", 'U', false, ModifiedScopeUnchanged},
		{"Changed", 'C', false, ModifiedScopeChanged},
		{"Invalid", 'Z', true, nil},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			v, err := GetModifiedScope(tc.value)
			if tc.wantErr {
				assert.Error(t, err)
				assert.Nil(t, v)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, v)
			}
		})
	}
}

// TestGetModifiedConfidentiality 测试获取修改后的机密性
func TestGetModifiedConfidentiality(t *testing.T) {
	testCases := []struct {
		name     string
		value    rune
		wantErr  bool
		expected Vector
	}{
		{"NotDefined", 'X', false, ConfidentialityNotDefined},
		{"None", 'N', false, ModifiedConfidentialityNone},
		{"Low", 'L', false, ModifiedConfidentialityLow},
		{"High", 'H', false, ModifiedConfidentialityHigh},
		{"Invalid", 'Z', true, nil},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			v, err := GetModifiedConfidentiality(tc.value)
			if tc.wantErr {
				assert.Error(t, err)
				assert.Nil(t, v)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, v)
			}
		})
	}
}

// TestGetModifiedIntegrity 测试获取修改后的完整性
func TestGetModifiedIntegrity(t *testing.T) {
	testCases := []struct {
		name     string
		value    rune
		wantErr  bool
		expected Vector
	}{
		{"NotDefined", 'X', false, IntegrityNotDefined},
		{"None", 'N', false, ModifiedIntegrityNone},
		{"Low", 'L', false, ModifiedIntegrityLow},
		{"High", 'H', false, ModifiedIntegrityHigh},
		{"Invalid", 'Z', true, nil},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			v, err := GetModifiedIntegrity(tc.value)
			if tc.wantErr {
				assert.Error(t, err)
				assert.Nil(t, v)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, v)
			}
		})
	}
}

// TestGetModifiedAvailability 测试获取修改后的可用性
func TestGetModifiedAvailability(t *testing.T) {
	testCases := []struct {
		name     string
		value    rune
		wantErr  bool
		expected Vector
	}{
		{"NotDefined", 'X', false, AvailabilityNotDefined},
		{"None", 'N', false, ModifiedAvailabilityNone},
		{"Low", 'L', false, ModifiedAvailabilityLow},
		{"High", 'H', false, ModifiedAvailabilityHigh},
		{"Invalid", 'Z', true, nil},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			v, err := GetModifiedAvailability(tc.value)
			if tc.wantErr {
				assert.Error(t, err)
				assert.Nil(t, v)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, v)
			}
		})
	}
}

// TestGetModifiedAttackVectorFull 补全 GetModifiedAttackVector 的 A/L/P 分支
func TestGetModifiedAttackVectorFull(t *testing.T) {
	testCases := []struct {
		name     string
		value    rune
		wantErr  bool
		expected Vector
	}{
		{"Adjacent", 'A', false, ModifiedAttackVectorAdjacent},
		{"Local", 'L', false, ModifiedAttackVectorLocal},
		{"Physical", 'P', false, ModifiedAttackVectorPhysical},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			v, err := GetModifiedAttackVector(tc.value)
			assert.NoError(t, err)
			assert.Equal(t, tc.expected, v)
		})
	}
}

// TestGetModifiedPrivilegesRequiredFull 补全 GetModifiedPrivilegesRequired 的 L/H 分支
func TestGetModifiedPrivilegesRequiredFull(t *testing.T) {
	testCases := []struct {
		name     string
		value    rune
		wantErr  bool
		expected Vector
	}{
		{"Low", 'L', false, ModifiedPrivilegesRequiredLow},
		{"High", 'H', false, ModifiedPrivilegesRequiredHigh},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			v, err := GetModifiedPrivilegesRequired(tc.value)
			assert.NoError(t, err)
			assert.Equal(t, tc.expected, v)
		})
	}
}

// TestGetPrivilegesRequiredScore 测试考虑 Scope 依赖后的 PR 分数
func TestGetPrivilegesRequiredScore(t *testing.T) {
	testCases := []struct {
		name         string
		pr           Vector
		scopeChanged bool
		expected     float64
	}{
		{"nil returns 1.0", nil, false, 1.0},
		{"nil returns 1.0 (scope changed)", nil, true, 1.0},
		{"None = 0.85 (unchanged)", PrivilegesRequiredNone, false, 0.85},
		{"None = 0.85 (changed)", PrivilegesRequiredNone, true, 0.85},
		{"Low = 0.62 (unchanged)", PrivilegesRequiredLow, false, 0.62},
		{"Low = 0.68 (changed)", PrivilegesRequiredLow, true, 0.68},
		{"High = 0.27 (unchanged)", PrivilegesRequiredHigh, false, 0.27},
		{"High = 0.5 (changed)", PrivilegesRequiredHigh, true, 0.5},
		{"Modified Low = 0.62 (unchanged)", ModifiedPrivilegesRequiredLow, false, 0.62},
		{"Modified Low = 0.68 (changed)", ModifiedPrivilegesRequiredLow, true, 0.68},
		{"Modified High = 0.27 (unchanged)", ModifiedPrivilegesRequiredHigh, false, 0.27},
		{"Modified High = 0.5 (changed)", ModifiedPrivilegesRequiredHigh, true, 0.5},
		{"NotDefined (X) returns 1.0", PrivilegesRequiredNotDefined, false, 1.0},
		{"NotDefined (X) returns 1.0 (changed)", PrivilegesRequiredNotDefined, true, 1.0},
		{"Unknown value falls back to GetScore", &VectorImpl{ShortValue: 'Q', Score: 0.42}, false, 0.42},
		{"Unknown value falls back to GetScore (changed)", &VectorImpl{ShortValue: 'Q', Score: 0.99}, true, 0.99},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := GetPrivilegesRequiredScore(tc.pr, tc.scopeChanged)
			assert.Equal(t, tc.expected, got)
		})
	}
}

// TestIsScopeChanged 测试 Scope 向量是否为 Changed
func TestIsScopeChanged(t *testing.T) {
	testCases := []struct {
		name     string
		scope    Vector
		expected bool
	}{
		{"nil scope", nil, false},
		{"Unchanged", ScopeUnchanged, false},
		{"Changed", ScopeChanged, true},
		{"Modified Unchanged", ModifiedScopeUnchanged, false},
		{"Modified Changed", ModifiedScopeChanged, true},
		{"NotDefined (X)", ScopeNotDefined, false},
		{"unrelated vector", PrivilegesRequiredNone, false},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, IsScopeChanged(tc.scope))
		})
	}
}

// TestIsModifiedScopeChanged 测试 Modified Scope 是否为 Changed，含回退逻辑
func TestIsModifiedScopeChanged(t *testing.T) {
	testCases := []struct {
		name          string
		modifiedScope Vector
		baseScope     Vector
		expected      bool
	}{
		{"modified changed, base unchanged", ModifiedScopeChanged, ScopeUnchanged, true},
		{"modified unchanged, base changed", ModifiedScopeUnchanged, ScopeChanged, false},
		{"modified not defined, base changed (fallback)", ScopeNotDefined, ScopeChanged, true},
		{"modified not defined, base unchanged (fallback)", ScopeNotDefined, ScopeUnchanged, false},
		{"modified nil, base changed (fallback)", nil, ScopeChanged, true},
		{"modified nil, base unchanged (fallback)", nil, ScopeUnchanged, false},
		{"modified nil, base nil", nil, nil, false},
		{"modified not defined, base nil (fallback)", ScopeNotDefined, nil, false},
		{"modified changed, base nil", ModifiedScopeChanged, nil, true},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, IsModifiedScopeChanged(tc.modifiedScope, tc.baseScope))
		})
	}
}

// TestGetUserInteractionScore 测试用户交互分数，考虑 CVSS 版本差异
func TestGetUserInteractionScore(t *testing.T) {
	testCases := []struct {
		name         string
		ui           Vector
		minorVersion int
		expected     float64
	}{
		{"nil returns 1.0", nil, 1, 1.0},
		{"nil returns 1.0 (v3.0)", nil, 0, 1.0},
		{"None = 0.85 (v3.1)", UserInteractionNone, 1, 0.85},
		{"None = 0.85 (v3.0)", UserInteractionNone, 0, 0.85},
		{"Required = 0.62 (v3.1)", UserInteractionRequired, 1, 0.62},
		{"Required = 0.56 (v3.0)", UserInteractionRequired, 0, 0.56},
		{"Modified None = 0.85 (v3.1)", ModifiedUserInteractionNone, 1, 0.85},
		{"Modified Required = 0.62 (v3.1)", ModifiedUserInteractionRequired, 1, 0.62},
		{"Modified Required = 0.56 (v3.0)", ModifiedUserInteractionRequired, 0, 0.56},
		{"NotDefined (X) returns 1.0 (v3.1)", UserInteractionNotDefined, 1, 1.0},
		{"NotDefined (X) returns 1.0 (v3.0)", UserInteractionNotDefined, 0, 1.0},
		{"Required v3.1 with minorVersion=2 still 0.62", UserInteractionRequired, 2, 0.62},
		{"Unknown value falls back to GetScore", &VectorImpl{ShortValue: 'Q', Score: 0.77}, 1, 0.77},
		{"Unknown value falls back to GetScore (v3.0)", &VectorImpl{ShortValue: 'Q', Score: 0.33}, 0, 0.33},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := GetUserInteractionScore(tc.ui, tc.minorVersion)
			assert.Equal(t, tc.expected, got)
		})
	}
}

// TestIsNotDefined 测试 VectorImpl.IsNotDefined
func TestIsNotDefined(t *testing.T) {
	testCases := []struct {
		name     string
		vector   *VectorImpl
		expected bool
	}{
		{"X is NotDefined", &VectorImpl{ShortValue: 'X'}, true},
		{"N is not NotDefined", &VectorImpl{ShortValue: 'N'}, false},
		{"L is not NotDefined", &VectorImpl{ShortValue: 'L'}, false},
		{"empty rune is not NotDefined", &VectorImpl{ShortValue: 0}, false},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.vector.IsNotDefined())
		})
	}
}
