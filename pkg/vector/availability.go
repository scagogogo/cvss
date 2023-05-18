package vector

type Availability struct {
	*VectorImpl
}

var _ Vector = &Availability{}

var (
	AvailabilityHigh = &Availability{
		VectorImpl: &VectorImpl{
			GroupName:   "Base Metrics",
			ShortName:   "A",
			LongName:    "Availability",
			ShortValue:  'H',
			LongValue:   "High",
			Description: `There is a total loss of availability, resulting in the attacker being able to fully deny access to resources in the impacted component; this loss is either sustained (while the attacker continues to deliver the attack) or persistent (the condition persists even after the attack has completed). Alternatively, the attacker has the ability to deny some availability, but the loss of availability presents a direct, serious consequence to the impacted component (e.g., the attacker cannot disrupt existing connections, but can prevent new connections; the attacker can repeatedly exploit a vulnerability that, in each instance of a successful attack, leaks a only small amount of memory, but after repeated exploitation causes a service to become completely unavailable).`,
			Score:       0.56,
		},
	}

	AvailabilityLow = &Availability{
		VectorImpl: &VectorImpl{
			GroupName:   "Base Metrics",
			ShortName:   "A",
			LongName:    "Availability",
			ShortValue:  'L',
			LongValue:   "Low",
			Description: `Performance is reduced or there are interruptions in resource availability. Even if repeated exploitation of the vulnerability is possible, the attacker does not have the ability to completely deny service to legitimate users. The resources in the impacted component are either partially available all of the time, or fully available only some of the time, but overall there is no direct, serious consequence to the impacted component.`,
			Score:       0.22,
		},
	}

	AvailabilityNone = &Availability{
		VectorImpl: &VectorImpl{
			GroupName:   "Base Metrics",
			ShortName:   "A",
			LongName:    "Availability",
			ShortValue:  'N',
			LongValue:   "None",
			Description: `There is no impact to availability within the impacted component.`,
			Score:       0,
		},
	}
)

var (
	ModifiedAvailabilityHigh = &Availability{
		VectorImpl: &VectorImpl{
			GroupName:   "Environmental",
			ShortName:   "MA",
			LongName:    "Modified Availability",
			ShortValue:  'H',
			LongValue:   "High",
			Description: `There is a total loss of availability, resulting in the attacker being able to fully deny access to resources in the impacted component; this loss is either sustained (while the attacker continues to deliver the attack) or persistent (the condition persists even after the attack has completed). Alternatively, the attacker has the ability to deny some availability, but the loss of availability presents a direct, serious consequence to the impacted component (e.g., the attacker cannot disrupt existing connections, but can prevent new connections; the attacker can repeatedly exploit a vulnerability that, in each instance of a successful attack, leaks a only small amount of memory, but after repeated exploitation causes a service to become completely unavailable).`,
			Score:       0.56,
		},
	}

	ModifiedAvailabilityLow = &Availability{
		VectorImpl: &VectorImpl{
			GroupName:   "Environmental",
			ShortName:   "MA",
			LongName:    "Modified Availability",
			ShortValue:  'L',
			LongValue:   "Low",
			Description: `Performance is reduced or there are interruptions in resource availability. Even if repeated exploitation of the vulnerability is possible, the attacker does not have the ability to completely deny service to legitimate users. The resources in the impacted component are either partially available all of the time, or fully available only some of the time, but overall there is no direct, serious consequence to the impacted component.`,
			Score:       0.22,
		},
	}

	ModifiedAvailabilityNone = &Availability{
		VectorImpl: &VectorImpl{
			GroupName:   "Environmental",
			ShortName:   "MA",
			LongName:    "Modified Availability",
			ShortValue:  'N',
			LongValue:   "None",
			Description: `There is no impact to availability within the impacted component.`,
			Score:       0,
		},
	}
)
