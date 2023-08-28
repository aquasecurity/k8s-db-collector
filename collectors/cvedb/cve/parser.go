package cve

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"

	"github.com/hashicorp/go-multierror"

	"github.com/aquasecurity/go-version/pkg/version"
	"github.com/aquasecurity/k8s-db-collector/collectors/cvedb/utils"
)

const (
	paragraph = `^\*[\s\S]*\*$`
	header    = `(^#{1,6}\s*[\S]+)`
)

func parseOfficialK8sCve(item interface{}, mid string) (*Vulnerability, error) {
	i := item.(map[string]interface{})
	contentText := i["content_text"].(string)
	amendedDoc := extractComponentsAndDescFromOfficialK8sCve(contentText)
	c := getComponentFromDescriptionAndffected(amendedDoc.AffectedFixed, amendedDoc.Description)
	vulnerability := Vulnerability{
		ID:            mid,
		Summary:       i["summary"].(string),
		Urls:          []string{i["url"].(string), i["external_url"].(string)},
		CreatedAt:     i["date_published"].(string),
		AffectedFixed: amendedDoc.AffectedFixed,
		Description:   amendedDoc.Description,
		Component:     c,
	}
	return &vulnerability, nil
}

func getMultiIDs(id string) []string {
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

type CVEDoc struct {
	AffectedFixed string
	Description   string
}

func extractComponentsAndDescFromOfficialK8sCve(doc string) CVEDoc {
	var lineWriter bytes.Buffer
	docReader := strings.NewReader(doc)
	fileScanner := bufio.NewScanner(docReader)
	fileScanner.Split(bufio.ScanLines)

	var affectedFixed strings.Builder
	var description strings.Builder
	var startAffected, endAffected bool
	var startFixed, endFixed bool
	for fileScanner.Scan() {
		line := fileScanner.Text()
		if endAffected && endFixed {
			break
		}
		if utils.MatchRegEx(paragraph, line) || utils.MatchRegEx(header, line) {
			if strings.Contains(strings.ToLower(line), "affected versions") {
				line = "#### Affected Versions"
				lineWriter.WriteString(fmt.Sprintf("%s\n", line))
				startAffected = true
				continue
			}
			if strings.Contains(strings.ToLower(line), "fixed versions") {
				line = "#### Fixed Versions"
				lineWriter.WriteString(fmt.Sprintf("%s\n", line))
				startFixed = true
				endAffected = true
				continue
			}
		}
		// add description
		if !(startAffected || startFixed) {
			description.WriteString(fmt.Sprintf("%s\n", line))
			continue
		}
		// complete version parsing
		if utils.MatchRegEx(header, line) && !strings.Contains(strings.ToLower(line), "fixed versions") && startFixed {
			endFixed = true
		}

		if len(strings.TrimSpace(line)) == 0 {
			continue
		}
		affectedFixed.WriteString(fmt.Sprintf("%s\n", line))
	}
	return CVEDoc{
		AffectedFixed: affectedFixed.String(),
		Description:   description.String(),
	}
}

func ValidateCveData(cves []*Vulnerability) error {
	var result error
	for _, cve := range cves {
		if len(cve.ID) == 0 {
			result = multierror.Append(result, fmt.Errorf("\nid is mssing on cve #%s", cve.ID))
		}
		if len(cve.CreatedAt) == 0 {
			result = multierror.Append(result, fmt.Errorf("\nCreatedAt is mssing on cve #%s", cve.ID))
		}
		if len(cve.Summary) == 0 {
			result = multierror.Append(result, fmt.Errorf("\nSummary is mssing on cve #%s", cve.ID))
		}
		if len(strings.TrimPrefix(cve.Component, upstreamOrgByName(cve.Component))) == 0 {
			result = multierror.Append(result, fmt.Errorf("\nComponent is mssing on cve #%s", cve.ID))
		}
		if len(cve.Description) == 0 {
			result = multierror.Append(result, fmt.Errorf("\nDescription is mssing on cve #%s", cve.ID))
		}
		if len(cve.Affected) == 0 {
			result = multierror.Append(result, fmt.Errorf("\nFixedVersion is missing on cve #%s", cve.ID))
		}
		if len(cve.Affected) > 0 {
			for _, v := range cve.AffectedVersions {
				_, err := version.Parse(v.Introduced)
				if err != nil {
					result = multierror.Append(result, fmt.Errorf("\nAffectedVersion From %s is invalid on cve #%s", v.Introduced, cve.ID))
				}
			}
		}
		if cve.CvssV3.Score == 0 {
			result = multierror.Append(result, fmt.Errorf("\nVector is mssing on cve #%s", cve.ID))
		}
		if cve.CvssV3.Vector == "" {
			result = multierror.Append(result, fmt.Errorf("\nVector is mssing on cve #%s", cve.ID))
		}
		if cve.Severity == "" {
			result = multierror.Append(result, fmt.Errorf("\nSeverity is mssing on cve #%s", cve.ID))
		}
		if len(cve.Urls) == 0 {
			result = multierror.Append(result, fmt.Errorf("\nUrls is mssing on cve #%s", cve.ID))
		}
	}
	return result
}

func upstreamOrgByName(component string) string {
	for key, components := range upstreamOrgName {
		for _, c := range strings.Split(components, ",") {
			if strings.TrimSpace(c) == strings.ToLower(component) {
				return key
			}
		}
	}
	return ""
}

func upstreamRepoByName(component string) string {
	if val, ok := upstreamRepoName[component]; ok {
		return val
	}
	return component
}

func getComponentFromDescriptionAndffected(descriptions ...string) string {
	var compName string
	var compCounter int
	var kubeCtlVersionFound bool
	for _, d := range descriptions {
		for key, value := range upstreamRepoName {
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
