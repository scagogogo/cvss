package vector

type Confidentiality struct {
	*VectorImpl
}

var _ Vector = &Confidentiality{}

var (
	ConfidentialityHigh = &Confidentiality{
		VectorImpl: &VectorImpl{
			GroupName:   "Base Metrics",
			ShortName:   "C",
			LongName:    "Confidentiality",
			ShortValue:  'H',
			LongValue:   "High",
			Description: `There is a total loss of confidentiality, resulting in all resources within the impacted component being divulged to the attacker. Alternatively, access to only some restricted information is obtained, but the disclosed information presents a direct, serious impact. For example, an attacker steals the administrator's password, or private encryption keys of a web server.`,
			Score:       0.56,
		},
	}

	ConfidentialityLow = &Confidentiality{
		VectorImpl: &VectorImpl{
			GroupName:   "Base Metrics",
			ShortName:   "C",
			LongName:    "Confidentiality",
			ShortValue:  'L',
			LongValue:   "Low",
			Description: `There is some loss of confidentiality. Access to some restricted information is obtained, but the attacker does not have control over what information is obtained, or the amount or kind of loss is limited. The information disclosure does not cause a direct, serious loss to the impacted component.`,
			Score:       0.22,
		},
	}

	ConfidentialityNone = &Confidentiality{
		VectorImpl: &VectorImpl{
			GroupName:   "Base Metrics",
			ShortName:   "C",
			LongName:    "Confidentiality",
			ShortValue:  'N',
			LongValue:   "None",
			Description: `There is no loss of confidentiality within the impacted component.`,
			Score:       0,
		},
	}
)

var (
	ModifiedConfidentialityHigh = &Confidentiality{
		VectorImpl: &VectorImpl{
			GroupName:   "Environmental",
			ShortName:   "MC",
			LongName:    "Modified Confidentiality",
			ShortValue:  'H',
			LongValue:   "High",
			Description: `There is a total loss of confidentiality, resulting in all resources within the impacted component being divulged to the attacker. Alternatively, access to only some restricted information is obtained, but the disclosed information presents a direct, serious impact. For example, an attacker steals the administrator's password, or private encryption keys of a web server.`,
			Score:       0.56,
		},
	}

	ModifiedConfidentialityLow = &Confidentiality{
		VectorImpl: &VectorImpl{
			GroupName:   "Environmental",
			ShortName:   "MC",
			LongName:    "Modified Confidentiality",
			ShortValue:  'L',
			LongValue:   "Low",
			Description: `There is some loss of confidentiality. Access to some restricted information is obtained, but the attacker does not have control over what information is obtained, or the amount or kind of loss is limited. The information disclosure does not cause a direct, serious loss to the impacted component.`,
			Score:       0.22,
		},
	}

	ModifiedConfidentialityNone = &Confidentiality{
		VectorImpl: &VectorImpl{
			GroupName:   "Environmental",
			ShortName:   "MC",
			LongName:    "Modified Confidentiality",
			ShortValue:  'N',
			LongValue:   "None",
			Description: `There is no loss of confidentiality within the impacted component.`,
			Score:       0,
		},
	}
)
