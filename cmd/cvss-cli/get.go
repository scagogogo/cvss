package main

import (
	"fmt"

	"github.com/scagogogo/cvss-skills/pkg/parser"
	"github.com/spf13/cobra"
)

var getCmd = &cobra.Command{
	Use:   "get [vector-string] [metric-name]",
	Short: "Get a single metric value from a CVSS vector",
	Long: `Get the value of a single metric from a CVSS vector.

Outputs the short value character. Use --long to show the long name.

Flags:
  --format  Output format: text (default), json

Examples:
  cvss get "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" AV
  # Output: N
  cvss get --long "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" AV
  # Output: Network
  cvss get --format json "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" AV`,
	Args: cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		cv, err := parser.ParseString(args[0])
		if err != nil {
			dief("Parse error: %v\n", err)
		}

		metricName := args[1]
		shortVal, longVal, err := cv.GetMetricValue(metricName)
		if err != nil {
			dief("Error: %v\n", err)
		}

		showLong, _ := cmd.Flags().GetBool("long")
		format, _ := cmd.Flags().GetString("format")
		if format == "json" {
			out := map[string]interface{}{
				"metric": metricName,
				"value":  string(shortVal),
				"long":   longVal,
			}
			fmt.Println(marshalJSON(out))
		} else if showLong {
			fmt.Println(longVal)
		} else {
			fmt.Println(string(shortVal))
		}
	},
}

func init() {
	getCmd.Flags().Bool("long", false, "show long metric name instead of short value")
	getCmd.Flags().String("format", "text", "output format: text or json")
	rootCmd.AddCommand(getCmd)
}
