package vector

type RemediationLevel struct {
	*VectorImpl
}

var _ Vector = &RemediationLevel{}

var (
	RemediationLevelNotDefined = &RemediationLevel{
		VectorImpl: &VectorImpl{
			GroupName:   "Temporal Metrics",
			ShortName:   "RL",
			LongName:    "Remediation Level",
			ShortValue:  'X',
			LongValue:   "Not Defined",
			Description: `Assigning this value indicates there is insufficient information to choose one of the other values, and has no impact on the overall Temporal Score, i.e., it has the same effect on scoring as assigning Unavailable.`,
			Score:       1,
		},
	}

	RemediationLevelUnavailable = &RemediationLevel{
		VectorImpl: &VectorImpl{
			GroupName:   "Temporal Metrics",
			ShortName:   "RL",
			LongName:    "Remediation Level",
			ShortValue:  'U',
			LongValue:   "Unavailable",
			Description: `There is either no solution available or it is impossible to apply.`,
			Score:       1,
		},
	}

	RemediationLevelWorkaround = &RemediationLevel{
		VectorImpl: &VectorImpl{
			GroupName:   "Temporal Metrics",
			ShortName:   "RL",
			LongName:    "Remediation Level",
			ShortValue:  'W',
			LongValue:   "Workaround",
			Description: `There is an unofficial, non-vendor solution available. In some cases, users of the affected technology will create a patch of their own or provide steps to work around or otherwise mitigate the vulnerability.`,
			Score:       0.97,
		},
	}

	RemediationLevelTemporaryFix = &RemediationLevel{
		VectorImpl: &VectorImpl{
			GroupName:   "Temporal Metrics",
			ShortName:   "RL",
			LongName:    "Remediation Level",
			ShortValue:  'T',
			LongValue:   "Temporary Fix",
			Description: `There is an official but temporary fix available. This includes instances where the vendor issues a temporary hotfix, tool, or workaround.`,
			Score:       0.96,
		},
	}

	RemediationLevelOfficialFix = &RemediationLevel{
		VectorImpl: &VectorImpl{
			GroupName:   "Temporal Metrics",
			ShortName:   "RL",
			LongName:    "Remediation Level",
			ShortValue:  'O',
			LongValue:   "Official Fix",
			Description: `A complete vendor solution is available. Either the vendor has issued an official patch, or an upgrade is available.`,
			Score:       0.95,
		},
	}
)
