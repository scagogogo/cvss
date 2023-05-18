package parser

import (
	"fmt"
	"github.com/scagogogo/cvss-parser/pkg/vector"
)

var DefaultVectorParser = NewVectorParser()

type VectorParser struct {
	VectorMap map[string]map[rune]vector.Vector
}

func NewVectorParser() *VectorParser {
	x := &VectorParser{}

	// Attack Vector
	x.Add(vector.AttackVectorNetwork)
	x.Add(vector.AttackVectorAdjacent)
	x.Add(vector.AttackVectorLocal)
	x.Add(vector.AttackVectorPhysical)

	// Modified Attack Vector
	x.Add(vector.ModifiedAttackVectorNetwork)
	x.Add(vector.ModifiedAttackVectorAdjacent)
	x.Add(vector.ModifiedAttackVectorLocal)
	x.Add(vector.ModifiedAttackVectorPhysical)

	// Attack Complexity
	x.Add(vector.AttackComplexityLow)
	x.Add(vector.AttackComplexityHigh)

	// 	Modified Attack Complexity
	x.Add(vector.ModifiedAttackComplexityLow)
	x.Add(vector.ModifiedAttackComplexityHigh)

	// Privileges Required
	x.Add(vector.PrivilegesRequiredNone)
	x.Add(vector.PrivilegesRequiredLow)
	x.Add(vector.PrivilegesRequiredHigh)

	// Modified Privileges Required
	x.Add(vector.ModifiedPrivilegesRequiredNone)
	x.Add(vector.ModifiedPrivilegesRequiredLow)
	x.Add(vector.ModifiedPrivilegesRequiredHigh)

	// User Interaction (UI)
	x.Add(vector.UserInteractionNone)
	x.Add(vector.UserInteractionRequired)

	// Modified User Interaction (MUI)
	x.Add(vector.ModifiedUserInteractionNone)
	x.Add(vector.ModifiedUserInteractionRequired)

	// Scope (S)
	x.Add(vector.ScopeUnchanged)
	x.Add(vector.ScopeChanged)

	// Confidentiality (C)
	x.Add(vector.ConfidentialityHigh)
	x.Add(vector.ConfidentialityLow)
	x.Add(vector.ConfidentialityNone)

	// 	Modified Confidentiality (MC)
	x.Add(vector.ModifiedConfidentialityHigh)
	x.Add(vector.ModifiedConfidentialityLow)
	x.Add(vector.ModifiedConfidentialityNone)

	// Integrity (I)
	x.Add(vector.IntegrityHigh)
	x.Add(vector.IntegrityLow)
	x.Add(vector.IntegrityNone)

	// 	Modified Integrity (MI)
	x.Add(vector.ModifiedIntegrityHigh)
	x.Add(vector.ModifiedIntegrityLow)
	x.Add(vector.ModifiedIntegrityNone)

	// Availability (A)
	x.Add(vector.AvailabilityHigh)
	x.Add(vector.AvailabilityLow)
	x.Add(vector.AvailabilityNone)

	// 	Modified Availability (MA)
	x.Add(vector.ModifiedAvailabilityHigh)
	x.Add(vector.ModifiedAvailabilityLow)
	x.Add(vector.ModifiedAvailabilityNone)

	// Exploit Code Maturity (E)
	x.Add(vector.ExploitCodeMaturityNotDefined)
	x.Add(vector.ExploitCodeMaturityHigh)
	x.Add(vector.ExploitCodeMaturityFunctional)
	x.Add(vector.ExploitCodeMaturityProofOfConcept)
	x.Add(vector.ExploitCodeMaturityUnproven)

	// Remediation Level (RL)
	x.Add(vector.RemediationLevelNotDefined)
	x.Add(vector.RemediationLevelUnavailable)
	x.Add(vector.RemediationLevelWorkaround)
	x.Add(vector.RemediationLevelTemporaryFix)
	x.Add(vector.RemediationLevelOfficialFix)

	// Report Confidence (RC)
	x.Add(vector.ReportConfidenceNotDefined)
	x.Add(vector.ReportConfidenceConfirmed)
	x.Add(vector.ReportConfidenceReasonable)
	x.Add(vector.ReportConfidenceUnknown)

	// Confidentiality Requirement
	x.Add(vector.ConfidentialityRequirementNotDefined)
	x.Add(vector.ConfidentialityRequirementHigh)
	x.Add(vector.ConfidentialityRequirementMedium)
	x.Add(vector.ConfidentialityRequirementLow)

	// Integrity Requirement
	x.Add(vector.IntegrityRequirementNotDefined)
	x.Add(vector.IntegrityRequirementHigh)
	x.Add(vector.IntegrityRequirementMedium)
	x.Add(vector.IntegrityRequirementLow)

	// Availability Requirement
	x.Add(vector.AvailabilityRequirementNotDefined)
	x.Add(vector.AvailabilityRequirementHigh)
	x.Add(vector.AvailabilityRequirementMedium)
	x.Add(vector.AvailabilityRequirementLow)

	return x
}

func (x *VectorParser) Add(v vector.Vector) {
	if x.VectorMap == nil {
		x.VectorMap = make(map[string]map[rune]vector.Vector)
	}
	if x.VectorMap[v.GetShortName()] == nil {
		x.VectorMap[v.GetShortName()] = make(map[rune]vector.Vector)
	}
	x.VectorMap[v.GetShortName()][v.GetShortValue()] = v
}

func (x *VectorParser) Parse(vectorName string, vectorValue rune) (vector.Vector, error) {
	valueMap, exists := x.VectorMap[vectorName]
	if !exists {
		return nil, fmt.Errorf("vector name %s does not exist", vectorName)
	}
	v, exists := valueMap[vectorValue]
	if !exists {
		return nil, fmt.Errorf("vector value %s does not exist", string(vectorValue))
	}
	return v, nil
}
