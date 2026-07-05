package cvss

import (
	"encoding/csv"
	"fmt"
	"io"
	"strings"
)

// CSVHeader 返回 CSV 输出的表头
func CSVHeader() []string {
	return []string{
		"vector_string", "version",
		"base_score", "base_severity",
		"temporal_score", "temporal_severity",
		"environmental_score", "environmental_severity",
		"impact_sub_score", "exploitability_sub_score",
	}
}

// CSVRow 将 Cvss3x 转换为 CSV 行
// 包含向量字符串、版本号、各项评分和严重性
func (x *Cvss3x) CSVRow(calc *Calculator) ([]string, error) {
	if x == nil {
		return nil, nil
	}
	if calc == nil {
		calc = NewCalculator(x)
	}

	allScores, err := calc.GetAllScores()
	if err != nil {
		return nil, err
	}

	row := []string{
		x.String(),
		x.Version(),
		fmt.Sprintf("%.1f", allScores.BaseScore),
		string(allScores.BaseSeverity),
	}

	if allScores.HasTemporal {
		row = append(row,
			fmt.Sprintf("%.1f", allScores.TemporalScore),
			string(allScores.TemporalSeverity),
		)
	} else {
		row = append(row, "", "")
	}

	if allScores.HasEnvironmental {
		row = append(row,
			fmt.Sprintf("%.1f", allScores.EnvironmentalScore),
			string(allScores.EnvironmentalSeverity),
		)
	} else {
		row = append(row, "", "")
	}

	row = append(row,
		fmt.Sprintf("%.4f", allScores.ImpactSubScore),
		fmt.Sprintf("%.4f", allScores.ExploitabilitySubScore),
	)

	return row, nil
}

// WriteCSV 将多个 Cvss3x 写入 CSV
// 包含表头和每行的评分数据
//
// 用法:
//
//	var buf bytes.Buffer
//	cvss.WriteCSV(&buf, []*cvss.Cvss3x{v1, v2, v3})
//	fmt.Println(buf.String())
func WriteCSV(w io.Writer, vectors []*Cvss3x) error {
	cw := csv.NewWriter(w)

	// 写入表头。csv.Writer.Write 写入内部 buffer，错误延迟到 Flush，
	// 因此这里不检查 Write 的返回值，统一在下方 Flush 时捕获。
	_ = cw.Write(CSVHeader())

	// 写入每行
	for _, cv := range vectors {
		calc := NewCalculator(cv)
		row, err := cv.CSVRow(calc)
		if err != nil {
			return fmt.Errorf("failed to generate CSV row: %w", err)
		}
		if row == nil {
			continue
		}
		_ = cw.Write(row)
	}

	// Flush 时一并捕获所有写入错误（包括底层 writer 的失败）。
	cw.Flush()
	if err := cw.Error(); err != nil {
		return fmt.Errorf("failed to write CSV: %w", err)
	}

	return nil
}

// ReadCSV 从 CSV 读取 CVSS 向量
// 期望第一列为向量字符串，跳过表头
// 每行返回一个解析结果
//
// 用法:
//
//	file, _ := os.Open("vectors.csv")
//	defer file.Close()
//	results, err := cvss.ReadCSV(file)
func ReadCSV(r io.Reader) ([]*Cvss3x, error) {
	cr := csv.NewReader(r)

	// 跳过表头
	if _, err := cr.Read(); err != nil {
		return nil, fmt.Errorf("failed to read CSV header: %w", err)
	}

	var vectors []*Cvss3x
	for {
		record, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read CSV row: %w", err)
		}

		if len(record) == 0 || record[0] == "" {
			continue
		}

		cv, err := fromVectorString(strings.TrimSpace(record[0]))
		if err != nil {
			// 跳过无效行
			continue
		}
		vectors = append(vectors, cv)
	}

	return vectors, nil
}

// ReadCSVLax 从 CSV 读取 CVSS 向量，容错模式
// 返回解析结果和解析错误列表
func ReadCSVLax(r io.Reader) ([]*Cvss3x, []CSVReadError, error) {
	cr := csv.NewReader(r)

	// 尝试跳过表头（如果第一行看起来像表头）
	firstRow, err := cr.Read()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read CSV: %w", err)
	}

	var vectors []*Cvss3x
	var errors []CSVReadError
	rowNum := 1

	// 检查第一行是否是表头
	if len(firstRow) > 0 && !strings.HasPrefix(firstRow[0], "CVSS:") {
		// 是表头，跳过
		rowNum++
	} else {
		// 不是表头，解析第一行
		if cv, err := fromVectorString(strings.TrimSpace(firstRow[0])); err == nil {
			vectors = append(vectors, cv)
		} else {
			errors = append(errors, CSVReadError{Row: rowNum, Value: firstRow[0], Error: err})
		}
		rowNum++
	}

	for {
		record, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}

		rowNum++
		if len(record) == 0 || record[0] == "" {
			continue
		}

		cv, err := fromVectorString(strings.TrimSpace(record[0]))
		if err != nil {
			errors = append(errors, CSVReadError{Row: rowNum, Value: record[0], Error: err})
			continue
		}
		vectors = append(vectors, cv)
	}

	return vectors, errors, nil
}

// CSVReadError CSV 读取错误
type CSVReadError struct {
	Row   int    // 行号
	Value string // 原始值
	Error error  // 解析错误
}

// String 返回错误的可读表示
func (e CSVReadError) String() string {
	return fmt.Sprintf("row %d: %q: %v", e.Row, e.Value, e.Error)
}
