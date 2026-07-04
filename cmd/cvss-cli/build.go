package main

import (
	"fmt"
	"strings"

	"github.com/scagogogo/cvss-skills/pkg/cvss"
	"github.com/spf13/cobra"
)

var buildCmd = &cobra.Command{
	Use:   "build [flags]",
	Short: "Build a CVSS vector from individual metric values",
	Long: `Build a CVSS vector string from individual metric values using flags.

All 8 base metrics are required. Temporal and environmental metrics are optional.
Use the same short values as in CVSS vector strings (e.g., AV=N, AC=L).

Flags:
  --format  Output format: text (default), json

Examples:
  cvss build --AV=N --AC=L --PR=N --UI=N --S=U --C=H --I=H --A=H
  cvss build --AV=N --AC=L --PR=N --UI=N --S=U --C=H --I=H --A=H --E=F --RL=T --RC=C
  cvss build --cvss-version=3.0 --AV=N --AC=L --PR=N --UI=N --S=C --C=H --I=H --A=H
  cvss build --format json --AV=N --AC=L --PR=N --UI=N --S=U --C=H --I=H --A=H`,
	Run: func(cmd *cobra.Command, args []string) {
		metrics := map[string]string{
			"AV": mustGetString(cmd, "AV"),
			"AC": mustGetString(cmd, "AC"),
			"PR": mustGetString(cmd, "PR"),
			"UI": mustGetString(cmd, "UI"),
			"S":  mustGetString(cmd, "S"),
			"C":  mustGetString(cmd, "C"),
			"I":  mustGetString(cmd, "I"),
			"A":  mustGetString(cmd, "A"),
		}

		// Optional temporal
		for _, key := range []string{"E", "RL", "RC"} {
			if val := mustGetString(cmd, key); val != "" {
				metrics[key] = val
			}
		}

		// Optional environmental
		for _, key := range []string{"CR", "IR", "AR", "MAV", "MAC", "MPR", "MUI", "MS", "MC", "MI", "MA"} {
			if val := mustGetString(cmd, key); val != "" {
				metrics[key] = val
			}
		}

		cvssVersion, _ := cmd.Flags().GetString("cvss-version")
		metrics["version"] = strings.ToUpper(cvssVersion)

		cv, err := cvss.FromMap(metrics)
		if err != nil {
			dief("Build error: %v\n", err)
		}

		format, _ := cmd.Flags().GetString("format")
		if format == "json" {
			out := map[string]interface{}{
				"vectorString": cv.String(),
			}
			fmt.Println(marshalJSON(out))
		} else {
			fmt.Println(cv.String())
		}
	},
}

func init() {
	// Base metrics (required)
	buildCmd.Flags().String("AV", "", "Attack Vector (N/A/L/P)")
	buildCmd.Flags().String("AC", "", "Attack Complexity (L/H)")
	buildCmd.Flags().String("PR", "", "Privileges Required (N/L/H)")
	buildCmd.Flags().String("UI", "", "User Interaction (N/R)")
	buildCmd.Flags().String("S", "", "Scope (U/C)")
	buildCmd.Flags().String("C", "", "Confidentiality (H/L/N)")
	buildCmd.Flags().String("I", "", "Integrity (H/L/N)")
	buildCmd.Flags().String("A", "", "Availability (H/L/N)")

	// Temporal (optional)
	buildCmd.Flags().String("E", "", "Exploit Code Maturity (X/U/P/F/H)")
	buildCmd.Flags().String("RL", "", "Remediation Level (X/O/T/W/U)")
	buildCmd.Flags().String("RC", "", "Report Confidence (X/U/R/C)")

	// Environmental (optional)
	buildCmd.Flags().String("CR", "", "Confidentiality Requirement (X/H/M/L)")
	buildCmd.Flags().String("IR", "", "Integrity Requirement (X/H/M/L)")
	buildCmd.Flags().String("AR", "", "Availability Requirement (X/H/M/L)")
	buildCmd.Flags().String("MAV", "", "Modified Attack Vector (X/N/A/L/P)")
	buildCmd.Flags().String("MAC", "", "Modified Attack Complexity (X/L/H)")
	buildCmd.Flags().String("MPR", "", "Modified Privileges Required (X/N/L/H)")
	buildCmd.Flags().String("MUI", "", "Modified User Interaction (X/N/R)")
	buildCmd.Flags().String("MS", "", "Modified Scope (X/U/C)")
	buildCmd.Flags().String("MC", "", "Modified Confidentiality (X/H/L/N)")
	buildCmd.Flags().String("MI", "", "Modified Integrity (X/H/L/N)")
	buildCmd.Flags().String("MA", "", "Modified Availability (X/H/L/N)")

	buildCmd.Flags().String("cvss-version", "3.1", "CVSS spec version: 3.0 or 3.1")
	buildCmd.Flags().String("format", "text", "output format: text or json")

	// Mark base metrics as required
	for _, name := range []string{"AV", "AC", "PR", "UI", "S", "C", "I", "A"} {
		_ = buildCmd.MarkFlagRequired(name)
	}

	rootCmd.AddCommand(buildCmd)
}
