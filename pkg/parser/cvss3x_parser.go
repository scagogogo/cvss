package parser

import (
	"errors"
	"fmt"
	"github.com/scagogogo/cvss-parser/pkg/cvss"
	"strconv"
	"strings"
)

var (
	// ErrParserMagicHead 解析的时候魔术头不合法
	ErrParserMagicHead = errors.New("cvss 3.x parser error, magic head valid, it must equals 'CVSS' ")
)

const (
	CVSSMagicHead = "CVSS"
)

// Cvss3xParser
// CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H
type Cvss3xParser struct {
	cvss3xStr string
	csvv3x    *cvss.Cvss3x

	// 解析使用的上下文
	cvss3xRunes []rune
	i           int
}

func NewCvss3xParser(cvss3xStr string) *Cvss3xParser {
	return &Cvss3xParser{
		cvss3xStr: cvss3xStr,
	}
}

func (x *Cvss3xParser) Parse() (*cvss.Cvss3x, error) {
	x.csvv3x = cvss.NewCvss3x()

	if err := x.readVersion(); err != nil {
		return nil, err
	}

	// TODO 2023-5-19 02:48:13 一个向量一个向量的处理
	for {

	}

	return x.csvv3x, nil
}

// 读取魔术头，固定的CVSS
func (x *Cvss3xParser) readMagicHead() error {
	if len(x.cvss3xRunes) < 4 {
		return ErrParserMagicHead
	}
	if strings.ToUpper(string(x.cvss3xRunes[0:4])) != CVSSMagicHead {
		return ErrParserMagicHead
	}
	x.i += 4
	return nil
}

// 读取版本号
func (x *Cvss3xParser) readVersion() error {

	// 主版本号
	majorVersion, err := x.readMajorVersion()
	if err != nil {
		return err
	}
	x.csvv3x.MajorVersion = majorVersion

	// 副版本号
	minorVersion, err := x.readMinorVersion()
	if err != nil {
		return err
	}
	x.csvv3x.MinorVersion = minorVersion

	return nil
}

// 读取主版本
func (x *Cvss3xParser) readMajorVersion() (int, error) {
	slice := make([]rune, 0)
	for x.isNotEnd() {
		c := x.read()
		if c == '.' {
			break
		}
		slice = append(slice, c)
	}
	majorVersion, err := strconv.ParseInt(string(slice), 10, 64)
	if err != nil {
		return 0, err
	}
	return int(majorVersion), nil
}

// 读取副版本
func (x *Cvss3xParser) readMinorVersion() (int, error) {
	slice := make([]rune, 0)
	for x.isNotEnd() {
		c := x.read()
		if c == '.' {
			break
		}
		slice = append(slice, c)
	}
	majorVersion, err := strconv.ParseInt(string(slice), 10, 64)
	if err != nil {
		return 0, err
	}
	return int(majorVersion), nil
}

// 读取一个键
func (x *Cvss3xParser) readKey() (string, error) {

	// 首先必须是一个 /
	if x.read() != ':' {
		return "", fmt.Errorf("cvss3x %s synctax error at %d", x.cvss3xStr, x.i)
	}

	// 然后再是读到一个 : 或者是结束
	slice := make([]rune, 0)
	for x.isNotEnd() {
		c := x.read()
		if c == ':' {
			x.i--
			break
		}
		slice = append(slice, c)
	}
	return string(slice), nil
}

// 读取一个值
func (x *Cvss3xParser) readValue() (string, error) {

	// 首先必须是一个 :
	if x.read() != ':' {
		return "", fmt.Errorf("cvss3x %s synctax error at %d", x.cvss3xStr, x.i)
	}

	// 然后再是读到一个 / 或者是结束
	slice := make([]rune, 0)
	for x.isNotEnd() {
		c := x.read()
		if c == '/' {
			x.i--
			break
		}
		slice = append(slice, c)
	}
	return string(slice), nil
}

func (x *Cvss3xParser) isNotEnd() bool {
	return x.i < len(x.cvss3xRunes)
}

func (x *Cvss3xParser) read() rune {
	if x.i < len(x.cvss3xRunes) {
		return 0
	} else {
		c := x.cvss3xRunes[x.i]
		x.i++
		return c
	}
}
