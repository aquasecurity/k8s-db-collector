package utils

import (
	"fmt"

	"regexp"
	"strings"

	version "github.com/aquasecurity/go-pep440-version"
	"github.com/goark/go-cvss/v3/metric"
)

const (
	LessThanOrEqual = "lessThenOrEqual"
	LessThen        = "lessThen"
)

var (
	UpstreamOrgName = map[string]string{
		"k8s.io":      "controller-manager,kubelet,apiserver,kubectl,kubernetes,kube-scheduler,kube-proxy",
		"sigs.k8s.io": "secrets-store-csi-driver",
	}

	UpstreamRepoName = map[string]string{
		"kube-controller-manager":  "controller-manager",
		"kubelet":                  "kubelet",
		"kube-apiserver":           "apiserver",
		"kubectl":                  "kubectl",
		"kubernetes":               "kubernetes",
		"kube-scheduler":           "kube-scheduler",
		"kube-proxy":               "kube-proxy",
		"api server":               "apiserver",
		"secrets-store-csi-driver": "secrets-store-csi-driver",
	}
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

func ExtractVersions(lessOps, origVersion string, ftype string) (string, string) {
	var introduce, lastAffected string
	if (ftype == LessThen || ftype == LessThanOrEqual) && len(lessOps) > 0 {
		introduce = origVersion
		if origVersion != "0" {
			if strings.Count(introduce, ".") == 1 {
				introduce = introduce + ".0"
			} else {
				lIndex := strings.LastIndex(lessOps, ".")
				introduce = strings.TrimSpace(fmt.Sprintf("%s.%s", lessOps[:lIndex], "0"))
			}
		}
		if ftype == LessThanOrEqual {
			lastAffected = strings.TrimSpace(lessOps)
		}
		return introduce, lastAffected
	}

	validVersion := make([]string, 0)
	// clean unwanted strings from versions
	for key := range UpstreamRepoName {
		origVersion = strings.TrimSpace(strings.ReplaceAll(origVersion, key, ""))
	}
	versionParts := strings.Split(origVersion, " ")
	for _, p := range versionParts {
		candidate, err := version.Parse(p)
		if err != nil {
			continue
		}
		validVersion = append(validVersion, candidate.String())
	}
	if len(validVersion) == 1 {
		introduce = strings.TrimSpace(validVersion[0])
		return introduce, lastAffected
	}
	if len(validVersion) == 2 {
		return strings.TrimSpace(validVersion[0]), strings.TrimSpace(validVersion[1])
	}
	return introduce, lastAffected
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

func GetMultiIDs(id string) []string {
	var idsList []string
	if strings.Contains(id, ",") {
		idParts := strings.Split(id, ",")
		for _, p := range idParts {
			if strings.HasPrefix(strings.TrimSpace(p), "CVE-") {
				idsList = append(idsList, strings.TrimSpace(p))
			}
		}
		return idsList
	}
	return []string{id}
}

func UpstreamOrgByName(component string) string {
	for key, components := range UpstreamOrgName {
		for _, c := range strings.Split(components, ",") {
			if strings.TrimSpace(c) == strings.ToLower(component) {
				return key
			}
		}
	}
	return ""
}

func UpstreamRepoByName(component string) string {
	if val, ok := UpstreamRepoName[component]; ok {
		return val
	}
	return component
}

func GetComponentFromDescription(descriptions ...string) string {
	var compName string
	var compCounter int
	var kubeCtlVersionFound bool
	for _, d := range descriptions {
		for key, value := range UpstreamRepoName {
			if key == "kubernetes" {
				continue
			}
			if strings.Contains(strings.ToLower(d), key) {
				c := strings.Count(strings.ToLower(d), key)
				if value == compName {
					compCounter = compCounter + c
				}
				if strings.Contains(strings.ToLower(d), "kubectl version") {
					kubeCtlVersionFound = true
				}
				if c > compCounter {
					compCounter = c
					compName = value
				}
			}
		}
	}
	if kubeCtlVersionFound && compName == "kubectl" && compCounter == 1 {
		compName = ""
	}
	return compName
}
