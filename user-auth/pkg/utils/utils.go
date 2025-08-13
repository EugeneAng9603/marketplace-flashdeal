package utils

import (
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"
)

func CapitalizeFirstLetter(m string) string {
	if len(m) == 0 || len(m) == 1 {
		return m
	}
	return strings.ToUpper(m[:1]) + m[1:]
}

func FormatToSGT(t time.Time, format string) string {
	if t.IsZero() {
		return ""
	}
	loc, err := time.LoadLocation("Asia/Singapore")
	if err != nil {
		loc = time.FixedZone("SGT", 8*60*60)
	}
	return t.In(loc).Format(format)
}

func IfThenElse(condition bool, trueVal any, falseVal any) any {
	if condition {
		return trueVal
	}
	return falseVal
}

func NowSGT() string {
	return fmt.Sprintf("%s GMT+8\n", FormatToSGT(time.Now(), "2006-01-02 15:04:05"))
}

func StrToInt(val string) int {
	parsedValue, err := strconv.Atoi(val)
	if err != nil {
		log.Printf("[StrToInt][Error parsing string to int: %v]", err)
		return 0
	}
	return parsedValue
}

func StrToFloat(val string) float64 {
	parsedValue, err := strconv.ParseFloat(val, 64)
	if err != nil {
		log.Printf("[StrToFloat][Error parsing string to float64: %v]", err)
		return 0.0
	}
	return parsedValue
}

func StrToTime(val string) time.Time {
	t, err := time.Parse(time.RFC3339, val)
	if err != nil {
		log.Printf("[StrToTime][Error parsing string to time.Time: %v]", err)
		return time.Time{}
	}
	return t.UTC()
}
