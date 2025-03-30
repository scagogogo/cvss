package main

import (
	"fmt"
	"log"

	"github.com/scagogogo/cvss-parser/pkg/parser"
)

func main() {
	// 示例CVSS向量字符串
	cvssVector := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

	// 创建解析器
	p := parser.NewCvss3xParser(cvssVector)

	// 解析CVSS向量
	cvss3x, err := p.Parse()
	if err != nil {
		log.Fatalf("解析CVSS向量失败: %v", err)
	}

	// 转换为JSON格式
	jsonData, err := cvss3x.ToJSON(nil)
	if err != nil {
		log.Fatalf("转换为JSON失败: %v", err)
	}

	// 打印JSON
	fmt.Println(string(jsonData))
}
