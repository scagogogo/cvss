package main

import (
	"fmt"

	"github.com/scagogogo/cvss-skills/pkg/parser"
	"github.com/spf13/cobra"
)

var mapCmd = &cobra.Command{
	Use:   "map [vector-string]",
	Short: "Output CVSS vector as key=value pairs",
	Long: `Output a CVSS vector as key=value pairs, useful for scripting.

Flags:
  --format  Output format: text (default), json

Examples:
  cvss map "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
  # Output:
  # AV=N
  # AC=L
  # PR=N
  # ...
  cvss map --format json "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		cv, err := parser.ParseString(args[0])
		if err != nil {
			dief("Parse error: %v\n", err)
		}

		m := cv.ToMap()
		// Print in canonical order
		order := []string{"version", "AV", "AC", "PR", "UI", "S", "C", "I", "A",
			"E", "RL", "RC", "CR", "IR", "AR", "MAV", "MAC", "MPR", "MUI", "MS", "MC", "MI", "MA"}

		format, _ := cmd.Flags().GetString("format")
		if format == "json" {
			out := map[string]interface{}{}
			for _, key := range order {
				if val, ok := m[key]; ok {
					out[key] = val
				}
			}
			fmt.Println(marshalJSON(out))
			return
		}

		for _, key := range order {
			if val, ok := m[key]; ok {
				fmt.Printf("%s=%s\n", key, val)
			}
		}
	},
}

func init() {
	mapCmd.Flags().String("format", "text", "output format: text or json")
	rootCmd.AddCommand(mapCmd)
}
