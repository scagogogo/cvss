package vector

type AttackVector struct {
	*VectorImpl
}

var _ Vector = &AttackVector{}

var (
	AttackVectorNetwork = &AttackVector{
		VectorImpl: &VectorImpl{
			GroupName:   "Base Metrics",
			ShortName:   "AV",
			LongName:    "Attack Vector",
			ShortValue:  'N',
			LongValue:   "Network",
			Description: `The vulnerable component is bound to the network stack and the set of possible attackers extends beyond the other options listed below, up to and including the entire Internet. Such a vulnerability is often termed “remotely exploitable” and can be thought of as an attack being exploitable at the protocol level one or more network hops away (e.g., across one or more routers). An example of a network attack is an attacker causing a denial of service (DoS) by sending a specially crafted TCP packet across a wide area network (e.g., CVE‑2004‑0230).`,
			Score:       0.85,
		},
	}

	AttackVectorAdjacent = &AttackVector{
		VectorImpl: &VectorImpl{
			GroupName:   "Base Metrics",
			ShortName:   "AV",
			LongName:    "Attack Vector",
			ShortValue:  'A',
			LongValue:   "Adjacent",
			Description: `The vulnerable component is bound to the network stack, but the attack is limited at the protocol level to a logically adjacent topology. This can mean an attack must be launched from the same shared physical (e.g., Bluetooth or IEEE 802.11) or logical (e.g., local IP subnet) network, or from within a secure or otherwise limited administrative domain (e.g., MPLS, secure VPN to an administrative network zone). One example of an Adjacent attack would be an ARP (IPv4) or neighbor discovery (IPv6) flood leading to a denial of service on the local LAN segment (e.g., CVE‑2013‑6014).`,
			Score:       0.62,
		},
	}

	AttackVectorLocal = &AttackVector{
		VectorImpl: &VectorImpl{
			GroupName:  "Base Metrics",
			ShortName:  "AV",
			LongName:   "Attack Vector",
			ShortValue: 'L',
			LongValue:  "Local",
			Description: `The vulnerable component is not bound to the network stack and the attacker’s path is via read/write/execute capabilities. Either:
the attacker exploits the vulnerability by accessing the target system locally (e.g., keyboard, console), or remotely (e.g., SSH); or
the attacker relies on User Interaction by another person to perform actions required to exploit the vulnerability (e.g., using social engineering techniques to trick a legitimate user into opening a malicious document).`,
			Score: 0.55,
		},
	}

	AttackVectorPhysical = &AttackVector{
		VectorImpl: &VectorImpl{
			GroupName:   "Base Metrics",
			ShortName:   "AV",
			LongName:    "Attack Vector",
			ShortValue:  'P',
			LongValue:   "Physical",
			Description: `The attack requires the attacker to physically touch or manipulate the vulnerable component. Physical interaction may be brief (e.g., evil maid attack[^1]) or persistent. An example of such an attack is a cold boot attack in which an attacker gains access to disk encryption keys after physically accessing the target system. Other examples include peripheral attacks via FireWire/USB Direct Memory Access (DMA).`,
			Score:       0.2,
		},
	}
)

var (
	ModifiedAttackVectorNetwork = &AttackVector{
		VectorImpl: &VectorImpl{
			GroupName:   "Environmental",
			ShortName:   "MAV",
			LongName:    "Modified Attack Vector",
			ShortValue:  'N',
			LongValue:   "Network",
			Description: `The vulnerable component is bound to the network stack and the set of possible attackers extends beyond the other options listed below, up to and including the entire Internet. Such a vulnerability is often termed “remotely exploitable” and can be thought of as an attack being exploitable at the protocol level one or more network hops away (e.g., across one or more routers). An example of a network attack is an attacker causing a denial of service (DoS) by sending a specially crafted TCP packet across a wide area network (e.g., CVE‑2004‑0230).`,
			Score:       0.85,
		},
	}

	ModifiedAttackVectorAdjacent = &AttackVector{
		VectorImpl: &VectorImpl{
			GroupName:   "Environmental",
			ShortName:   "MAV",
			LongName:    "Modified Attack Vector",
			ShortValue:  'A',
			LongValue:   "Adjacent",
			Description: `The vulnerable component is bound to the network stack, but the attack is limited at the protocol level to a logically adjacent topology. This can mean an attack must be launched from the same shared physical (e.g., Bluetooth or IEEE 802.11) or logical (e.g., local IP subnet) network, or from within a secure or otherwise limited administrative domain (e.g., MPLS, secure VPN to an administrative network zone). One example of an Adjacent attack would be an ARP (IPv4) or neighbor discovery (IPv6) flood leading to a denial of service on the local LAN segment (e.g., CVE‑2013‑6014).`,
			Score:       0.62,
		},
	}

	ModifiedAttackVectorLocal = &AttackVector{
		VectorImpl: &VectorImpl{
			GroupName:  "Environmental",
			ShortName:  "MAV",
			LongName:   "Modified Attack Vector",
			ShortValue: 'L',
			LongValue:  "Local",
			Description: `The vulnerable component is not bound to the network stack and the attacker’s path is via read/write/execute capabilities. Either:
the attacker exploits the vulnerability by accessing the target system locally (e.g., keyboard, console), or remotely (e.g., SSH); or
the attacker relies on User Interaction by another person to perform actions required to exploit the vulnerability (e.g., using social engineering techniques to trick a legitimate user into opening a malicious document).`,
			Score: 0.55,
		},
	}

	ModifiedAttackVectorPhysical = &AttackVector{
		VectorImpl: &VectorImpl{
			GroupName:   "Environmental",
			ShortName:   "MAV",
			LongName:    "Modified Attack Vector",
			ShortValue:  'P',
			LongValue:   "Physical",
			Description: `The attack requires the attacker to physically touch or manipulate the vulnerable component. Physical interaction may be brief (e.g., evil maid attack[^1]) or persistent. An example of such an attack is a cold boot attack in which an attacker gains access to disk encryption keys after physically accessing the target system. Other examples include peripheral attacks via FireWire/USB Direct Memory Access (DMA).`,
			Score:       0.2,
		},
	}
)
