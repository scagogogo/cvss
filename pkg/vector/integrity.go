package vector

type Integrity struct {
	*VectorImpl
}

var _ Vector = &Integrity{}

var (
	IntegrityHigh = &Integrity{
		VectorImpl: &VectorImpl{
			GroupName:   "Base Metrics",
			ShortName:   "I",
			LongName:    "Integrity",
			ShortValue:  'H',
			LongValue:   "High",
			Description: `There is a total loss of integrity, or a complete loss of protection. For example, the attacker is able to modify any/all files protected by the impacted component. Alternatively, only some files can be modified, but malicious modification would present a direct, serious consequence to the impacted component.`,
			Score:       0.56,
		},
	}

	IntegrityLow = &Integrity{
		VectorImpl: &VectorImpl{
			GroupName:   "Base Metrics",
			ShortName:   "I",
			LongName:    "Integrity",
			ShortValue:  'L',
			LongValue:   "Low",
			Description: `Modification of data is possible, but the attacker does not have control over the consequence of a modification, or the amount of modification is limited. The data modification does not have a direct, serious impact on the impacted component.`,
			Score:       0.22,
		},
	}

	IntegrityNone = &Integrity{
		VectorImpl: &VectorImpl{
			GroupName:   "Base Metrics",
			ShortName:   "I",
			LongName:    "Integrity",
			ShortValue:  'N',
			LongValue:   "None",
			Description: `There is no loss of integrity within the impacted component.`,
			Score:       0,
		},
	}
)


var (
	ModifiedIntegrityHigh = &Integrity{
		VectorImpl: &VectorImpl{
			GroupName:   "Environmental",
			ShortName:   "MI",
			LongName:    "Modified Integrity",
			ShortValue:  'H',
			LongValue:   "High",
			Description: `There is a total loss of integrity, or a complete loss of protection. For example, the attacker is able to modify any/all files protected by the impacted component. Alternatively, only some files can be modified, but malicious modification would present a direct, serious consequence to the impacted component.`,
			Score:       0.56,
		},
	}

	ModifiedIntegrityLow = &Integrity{
		VectorImpl: &VectorImpl{
			GroupName:   "Environmental",
			ShortName:   "MI",
			LongName:    "Modified Integrity",
			ShortValue:  'L',
			LongValue:   "Low",
			Description: `Modification of data is possible, but the attacker does not have control over the consequence of a modification, or the amount of modification is limited. The data modification does not have a direct, serious impact on the impacted component.`,
			Score:       0.22,
		},
	}

	ModifiedIntegrityNone = &Integrity{
		VectorImpl: &VectorImpl{
			GroupName:   "Environmental",
			ShortName:   "MI",
			LongName:    "Modified Integrity",
			ShortValue:  'N',
			LongValue:   "None",
			Description: `There is no loss of integrity within the impacted component.`,
			Score:       0,
		},
	}
)

