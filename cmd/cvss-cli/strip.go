package main

import (
	"fmt"

	"github.com/scagogogo/cvss-skills/pkg/parser"
	"github.com/spf13/cobra"
)

var stripCmd = &cobra.Command{
	Use:     "base-only [vector-string]",
	Aliases: []string{"strip"},
	Short:   "Extract only base metrics from a CVSS vector",
	Long: `Strip temporal and environmental metrics, keeping only base metrics.

Flags:
  --format  Output format: text (default), json

Examples:
  cvss base-only "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:T/RC:C"
  cvss strip "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:T/RC:C/CR:H/IR:M/AR:L"
  cvss base-only --format json "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:T/RC:C"`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		cv, err := parser.ParseString(args[0])
		if err != nil {
			dief("Parse error: %v\n", err)
		}

		base := cv.BaseOnly()
		format, _ := cmd.Flags().GetString("format")
		if format == "json" {
			out := map[string]interface{}{
				"vector": base.String(),
			}
			fmt.Println(marshalJSON(out))
		} else {
			fmt.Println(base.String())
		}
	},
}

func init() {
	stripCmd.Flags().String("format", "text", "output format: text or json")
	rootCmd.AddCommand(stripCmd)
}
