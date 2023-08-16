package utils

import (
	"fmt"

	"regexp"
	"strings"

	version "github.com/aquasecurity/go-pep440-version"
	"github.com/goark/go-cvss/v3/metric"
)

func TrimString(version string, trimValues []string) string {
	for _, v := range trimValues {
		version = strings.ReplaceAll(version, v, "")
	}
	return strings.TrimSpace(version)
}

func MatchRegEx(regex string, value string) bool {
	headerRegex := regexp.MustCompile(regex)
	return len(headerRegex.FindStringSubmatch(value)) > 0

}

func VersionParts(line string) ([]string, string) {
	line = strings.TrimSpace(line)
	line = strings.TrimPrefix(line, "-")
	sign := "-"
	signs := []string{"<=", ">=", "<", ">"}
	for _, s := range signs {
		if strings.Contains(line, s) {
			sign = s
			break
		}
	}
	if sign != "-" {
		line = strings.ReplaceAll(line, sign, "")
	}
	updatedLine := fmt.Sprintf(" %s", line)
	findVersionParts := make([]string, 0)
	versionRex := `(?P<name>[^\s]+)?\s+v?(?P<version>\d+\.\d+\.\d+).*.v?(?P<version2>\d+\.\d+\.\d+)|\s*(\d+\.\d+\.\d+)\s*|(?P<name2>[^\s]+)?\s+v?(?P<version3>\d+\.\d+\.\d+)`
	regex := regexp.MustCompile(versionRex)
	parts := regex.FindStringSubmatch(updatedLine)
	if IsIP(updatedLine) {
		return findVersionParts, ""
	}
	for i, p := range parts {
		if i == 0 {
			continue
		}
		if len(p) == 0 {
			continue
		}
		findVersionParts = append(findVersionParts, p)
		if len(findVersionParts) == 1 && sign == "-" {
			sign = ""
		}
	}
	return findVersionParts, sign
}

func IsIP(value string) bool {
	ipregex := `(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])`
	regex := regexp.MustCompile(ipregex)
	parts := regex.FindStringSubmatch(value)
	return len(parts) > 0
}

func UpdatedLine(versionParts []string, sign string) string {
	switch len(versionParts) {
	case 1:
		return fmt.Sprintf("- %s v%s", sign, versionParts[0])
	case 2:
		var oneVersion bool
		var twoVersion bool
		if _, err := version.Parse(versionParts[0]); err == nil {
			oneVersion = true
		}
		if _, err := version.Parse(versionParts[1]); err == nil && oneVersion {
			twoVersion = true
			oneVersion = false
		} else {
			oneVersion = true
		}
		if twoVersion {
			return fmt.Sprintf("- v%s - v%s", versionParts[0], versionParts[1])
		}
		if oneVersion {
			return fmt.Sprintf("- %s %s v%s", versionParts[0], sign, versionParts[1])
		}
	case 3:
		return fmt.Sprintf("- %s v%s - v%s", versionParts[0], versionParts[1], versionParts[2])
	}
	return ""
}

func CvssVectorToScore(vector string) (string, float64) {
	bm, err := metric.NewBase().Decode(vector) //CVE-2020-1472: ZeroLogon
	if err != nil {
		return "", 0.0
	}
	return bm.Severity().String(), bm.Score()
}

func ExtractVersions(versionString string) (string, string) {
	if strings.HasPrefix(strings.TrimSpace(versionString), "<=") {
		tv := strings.ReplaceAll(strings.TrimSpace(versionString), "<=", "")
		return strings.TrimSpace(fmt.Sprintf("%s.%s", tv[:strings.LastIndex(tv, ".")], "0")), tv
	}
	if strings.HasPrefix(strings.TrimSpace(versionString), "<") {
		tv := strings.ReplaceAll(strings.TrimSpace(versionString), "<", "")
		return strings.TrimSpace(fmt.Sprintf("%s.%s", tv[:strings.LastIndex(tv, ".")], "0")), ""
	}
	validVersion := make([]string, 0)
	for _, c := range []string{"controller-manager, kubelet, apiserver, kubectl", "-"} {
		versionString = strings.TrimSpace(strings.ReplaceAll(versionString, c, ""))
	}
	versionParts := strings.Split(versionString, " ")
	for _, p := range versionParts {
		candidate, err := version.Parse(p)
		if err != nil {
			continue
		}
		validVersion = append(validVersion, candidate.String())
	}

	if len(validVersion) == 2 {
		return strings.TrimSpace(validVersion[0]), strings.TrimSpace(validVersion[1])
	}
	if len(validVersion) == 1 {
		return strings.TrimSpace(validVersion[0]), ""
	}
	return versionString, ""
}

func FindVersion(versionString string) string {
	versionParts := strings.Split(versionString, " ")
	if len(versionParts) == 1 {
		return strings.TrimSpace(versionString)
	}
	if len(versionParts) == 2 {
		for _, p := range versionParts {
			candidate, err := version.Parse(p)
			if err != nil {
				continue
			}
			return strings.TrimSpace(candidate.String())
		}
	}
	return versionString
}
