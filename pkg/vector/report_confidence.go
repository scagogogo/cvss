package vector

type ReportConfidence struct {
	*VectorImpl
}

var _ Vector = &ReportConfidence{}

var (
	ReportConfidenceNotDefined = &ReportConfidence{
		VectorImpl: &VectorImpl{
			GroupName:   "Temporal Metrics",
			ShortName:   "RC",
			LongName:    "Report Confidence",
			ShortValue:  'X',
			LongValue:   "Not Defined",
			Description: `Assigning this value indicates there is insufficient information to choose one of the other values, and has no impact on the overall Temporal Score, i.e., it has the same effect on scoring as assigning Confirmed.`,
			Score:       1,
		},
	}

	ReportConfidenceConfirmed = &ReportConfidence{
		VectorImpl: &VectorImpl{
			GroupName:   "Temporal Metrics",
			ShortName:   "RC",
			LongName:    "Report Confidence",
			ShortValue:  'C',
			LongValue:   "Confirmed",
			Description: `Detailed reports exist, or functional reproduction is possible (functional exploits may provide this). Source code is available to independently verify the assertions of the research, or the author or vendor of the affected code has confirmed the presence of the vulnerability.`,
			Score:       1,
		},
	}

	ReportConfidenceReasonable = &ReportConfidence{
		VectorImpl: &VectorImpl{
			GroupName:   "Temporal Metrics",
			ShortName:   "RC",
			LongName:    "Report Confidence",
			ShortValue:  'R',
			LongValue:   "Reasonable",
			Description: `Significant details are published, but researchers either do not have full confidence in the root cause, or do not have access to source code to fully confirm all of the interactions that may lead to the result. Reasonable confidence exists, however, that the bug is reproducible and at least one impact is able to be verified (proof-of-concept exploits may provide this). An example is a detailed write-up of research into a vulnerability with an explanation (possibly obfuscated or “left as an exercise to the reader”) that gives assurances on how to reproduce the results.`,
			Score:       0.96,
		},
	}

	ReportConfidenceUnknown = &ReportConfidence{
		VectorImpl: &VectorImpl{
			GroupName:   "Temporal Metrics",
			ShortName:   "RC",
			LongName:    "Report Confidence",
			ShortValue:  'U',
			LongValue:   "Unknown",
			Description: `There are reports of impacts that indicate a vulnerability is present. The reports indicate that the cause of the vulnerability is unknown, or reports may differ on the cause or impacts of the vulnerability. Reporters are uncertain of the true nature of the vulnerability, and there is little confidence in the validity of the reports or whether a static Base Score can be applied given the differences described. An example is a bug report which notes that an intermittent but non-reproducible crash occurs, with evidence of memory corruption suggesting that denial of service, or possible more serious impacts, may result.`,
			Score:       0.92,
		},
	}
)
