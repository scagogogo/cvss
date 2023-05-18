package vector

type ConfidentialityRequirement struct {
	*VectorImpl
}

var _ Vector = &ConfidentialityRequirement{}

var (
	ConfidentialityRequirementNotDefined = &ConfidentialityRequirement{
		VectorImpl: &VectorImpl{
			GroupName:   "Environmental Metrics",
			ShortName:   "CR",
			LongName:    "Confidentiality Requirement",
			ShortValue:  'X',
			LongValue:   "Not Defined",
			Description: `Assigning this value indicates there is insufficient information to choose one of the other values, and has no impact on the overall Environmental Score, i.e., it has the same effect on scoring as assigning Medium.`,
			Score:       1,
		},
	}

	ConfidentialityRequirementHigh = &ConfidentialityRequirement{
		VectorImpl: &VectorImpl{
			GroupName:   "Environmental Metrics",
			ShortName:   "CR",
			LongName:    "Confidentiality Requirement",
			ShortValue:  'H',
			LongValue:   "High",
			Description: `Loss of [Confidentiality | Integrity | Availability] is likely to have a catastrophic adverse effect on the organization or individuals associated with the organization (e.g., employees, customers).`,
			Score:       1.5,
		},
	}

	ConfidentialityRequirementMedium = &ConfidentialityRequirement{
		VectorImpl: &VectorImpl{
			GroupName:   "Environmental Metrics",
			ShortName:   "CR",
			LongName:    "Confidentiality Requirement",
			ShortValue:  'M',
			LongValue:   "Medium",
			Description: `Loss of [Confidentiality | Integrity | Availability] is likely to have a serious adverse effect on the organization or individuals associated with the organization (e.g., employees, customers).`,
			Score:       1,
		},
	}

	ConfidentialityRequirementLow = &ConfidentialityRequirement{
		VectorImpl: &VectorImpl{
			GroupName:   "Environmental Metrics",
			ShortName:   "CR",
			LongName:    "Confidentiality Requirement",
			ShortValue:  'L',
			LongValue:   "Low",
			Description: `Loss of [Confidentiality | Integrity | Availability] is likely to have only a limited adverse effect on the organization or individuals associated with the organization (e.g., employees, customers).`,
			Score:       0.5,
		},
	}
)
