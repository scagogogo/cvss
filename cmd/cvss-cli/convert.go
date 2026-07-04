package main

import (
	"fmt"
	"os"

	"github.com/scagogogo/cvss-skills/pkg/cvss"
	"github.com/scagogogo/cvss-skills/pkg/parser"
	"github.com/spf13/cobra"
)

var convertCmd = &cobra.Command{
	Use:   "convert [vector-string]",
	Short: "Convert CVSS vector between v3.0 and v3.1",
	Long: `Convert a CVSS vector from one version to another.

Supported conversions:
  - v3.0 → v3.1 (upgrade)
  - v3.1 → v3.0 (downgrade)

Note: Metric values remain the same; only the version number changes.
The UI:Required score differs between versions (0.56 in v3.0, 0.62 in v3.1),
so scores may change after conversion.

Flags:
  --format  Output format: text (default), json

Examples:
  cvss convert --to 3.0 "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
  cvss convert --to 3.1 "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
  cvss convert --format json --to 3.1 "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		targetVersion, _ := cmd.Flags().GetString("to")
		format, _ := cmd.Flags().GetString("format")

		cv, err := parser.ParseString(args[0])
		if err != nil {
			fmt.Fprintln(os.Stderr, "Parse error:", err)
			os.Exit(1)
		}

		var converted *cvss.Cvss3x
		switch targetVersion {
		case "3.0":
			converted, err = cv.DowngradeTo30()
		case "3.1":
			converted, err = cv.UpgradeTo31()
		default:
			fmt.Fprintln(os.Stderr, "Invalid target version (use 3.0 or 3.1)")
			os.Exit(1)
		}

		if err != nil {
			fmt.Fprintln(os.Stderr, "Conversion error:", err)
			os.Exit(1)
		}

		// Show both versions with scores
		calc1 := cvss.NewCalculator(cv)
		calc2 := cvss.NewCalculator(converted)
		s1, _ := calc1.Calculate()
		s2, _ := calc2.Calculate()

		if format == "json" {
			out := map[string]interface{}{
				"input":  cv.String(),
				"output": converted.String(),
				"from":   cv.Version(),
				"to":     targetVersion,
				"inputScore":  s1,
				"outputScore": s2,
			}
			fmt.Println(marshalJSON(out))
		} else {
			fmt.Printf("Original:  %s (%.1f)\n", cv.String(), s1)
			fmt.Printf("Converted: %s (%.1f)\n", converted.String(), s2)
		}
	},
}

func init() {
	convertCmd.Flags().String("to", "3.1", "target version: 3.0 or 3.1")
	convertCmd.Flags().String("format", "text", "output format: text or json")
	rootCmd.AddCommand(convertCmd)
}
