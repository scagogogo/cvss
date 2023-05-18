package vector

// AttackComplexity Attack Complexity / Modified Attack Complexity
type AttackComplexity struct {
	*VectorImpl
}

var _ Vector = &AttackComplexity{}

var (
	AttackComplexityLow = &AttackComplexity{
		VectorImpl: &VectorImpl{
			GroupName:   "Base Metrics",
			ShortName:   "AC",
			LongName:    "Attack Complexity",
			ShortValue:  'L',
			LongValue:   "Low",
			Description: `Specialized access conditions or extenuating circumstances do not exist. An attacker can expect repeatable success when attacking the vulnerable component.`,
			Score:       0.77,
		},
	}

	AttackComplexityHigh = &AttackComplexity{
		VectorImpl: &VectorImpl{
			GroupName:  "Base Metrics",
			ShortName:  "AC",
			LongName:   "Attack Complexity",
			ShortValue: 'H',
			LongValue:  "High",
			Description: `A successful attack depends on conditions beyond the attacker's control. That is, a successful attack cannot be accomplished at will, but requires the attacker to invest in some measurable amount of effort in preparation or execution against the vulnerable component before a successful attack can be expected.[^2] For example, a successful attack may depend on an attacker overcoming any of the following conditions:
The attacker must gather knowledge about the environment in which the vulnerable target/component exists. For example, a requirement to collect details on target configuration settings, sequence numbers, or shared secrets.
The attacker must prepare the target environment to improve exploit reliability. For example, repeated exploitation to win a race condition, or overcoming advanced exploit mitigation techniques.
The attacker must inject themselves into the logical network path between the target and the resource requested by the victim in order to read and/or modify network communications (e.g., a man in the middle attack).`,
			Score: 0.44,
		},
	}
)

var (
	ModifiedAttackComplexityLow = &AttackComplexity{
		VectorImpl: &VectorImpl{
			GroupName:   "Environmental",
			ShortName:   "MAC",
			LongName:    "Modified Attack Complexity",
			ShortValue:  'L',
			LongValue:   "Low",
			Description: `Specialized access conditions or extenuating circumstances do not exist. An attacker can expect repeatable success when attacking the vulnerable component.`,
			Score:       0.77,
		},
	}

	ModifiedAttackComplexityHigh = &AttackComplexity{
		VectorImpl: &VectorImpl{
			GroupName:  "Environmental",
			ShortName:  "MAC",
			LongName:   "Modified Attack Complexity",
			ShortValue: 'H',
			LongValue:  "High",
			Description: `A successful attack depends on conditions beyond the attacker's control. That is, a successful attack cannot be accomplished at will, but requires the attacker to invest in some measurable amount of effort in preparation or execution against the vulnerable component before a successful attack can be expected.[^2] For example, a successful attack may depend on an attacker overcoming any of the following conditions:
The attacker must gather knowledge about the environment in which the vulnerable target/component exists. For example, a requirement to collect details on target configuration settings, sequence numbers, or shared secrets.
The attacker must prepare the target environment to improve exploit reliability. For example, repeated exploitation to win a race condition, or overcoming advanced exploit mitigation techniques.
The attacker must inject themselves into the logical network path between the target and the resource requested by the victim in order to read and/or modify network communications (e.g., a man in the middle attack).`,
			Score: 0.44,
		},
	}
)
