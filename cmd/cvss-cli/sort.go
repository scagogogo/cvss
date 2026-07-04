package main

import (
	"fmt"
	"os"

	"github.com/scagogogo/cvss-skills/pkg/cvss"
	"github.com/scagogogo/cvss-skills/pkg/parser"
	"github.com/spf13/cobra"
)

var sortCmd = &cobra.Command{
	Use:   "sort [file]",
	Short: "Sort CVSS vectors by score",
	Long: `Read CVSS vectors from a file or stdin and sort them by score.

Default sort order is descending (highest score first).
Use --asc for ascending order.

Flags:
  --format  Output format: text (default), json

Examples:
  cvss sort vectors.txt
  cat vectors.txt | cvss sort -
  cvss sort --asc vectors.txt
  cvss sort --format json vectors.txt`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		asc, _ := cmd.Flags().GetBool("asc")
		format, _ := cmd.Flags().GetString("format")

		lines := readLines(cmd, args)
		if len(lines) == 0 {
			return
		}

		var vectors []*cvss.Cvss3x
		for _, line := range lines {
			cv, err := parser.ParseString(line)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Skipping invalid: %s\n", line)
				continue
			}
			vectors = append(vectors, cv)
		}

		if len(vectors) == 0 {
			return
		}

		slice := cvss.NewCvss3xSlice(vectors...)
		if asc {
			slice.Asc()
		}
		slice.Sort()

		if format == "json" {
			items := make([]map[string]interface{}, 0, len(slice.Items()))
			for _, cv := range slice.Items() {
				calc := cvss.NewCalculator(cv)
				score, _ := calc.Calculate()
				items = append(items, map[string]interface{}{
					"score":  score,
					"vector": cv.String(),
				})
			}
			out := map[string]interface{}{
				"items": items,
				"asc":   asc,
			}
			fmt.Println(marshalJSON(out))
			return
		}

		for _, cv := range slice.Items() {
			calc := cvss.NewCalculator(cv)
			score, _ := calc.Calculate()
			fmt.Printf("%.1f  %s\n", score, cv.String())
		}
	},
}

func init() {
	sortCmd.Flags().Bool("asc", false, "sort ascending (lowest score first)")
	sortCmd.Flags().String("format", "text", "output format: text or json")
	rootCmd.AddCommand(sortCmd)
}
