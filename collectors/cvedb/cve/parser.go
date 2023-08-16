package cve

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/hashicorp/go-multierror"

	"github.com/aquasecurity/go-version/pkg/version"
	"github.com/aquasecurity/k8s-db-collector/collectors/cvedb/utils"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
)

const (
	paragraph = `^\*[\s\S]*\*$`
	header    = `(^#{1,6}\s*[\S]+)`
)

type Vulnerability struct {
	ID               string     `json:"id,omitempty"`
	CreatedAt        string     `json:"created_at,omitempty"`
	Summary          string     `json:"summary,omitempty"`
	Component        string     `json:"component,omitempty"`
	Description      string     `json:"description,omitempty"`
	AffectedVersions []*Version `json:"affected_versions,omitempty"`
	FixedVersions    []*Version `json:"-"`
	Urls             []string   `json:"urls,omitempty"`
	CvssV3           Cvssv3     `json:"cvssv3,omitempty"`
	Severity         string     `json:"severity,omitempty"`
}

type K8sVulnDB struct {
	Cves []*Vulnerability
}

type Cvssv3 struct {
	Vector string
	Score  float64
}

func ParseVulnItem(item interface{}, mid string) (*Vulnerability, error) {
	gm := goldmark.New(
		goldmark.WithExtensions(
			extension.GFM, // GitHub flavoured markdown.
		),
		goldmark.WithParserOptions(
			parser.WithAttribute(), // Enables # headers {#custom-ids}.
		),
		goldmark.WithRenderer(NewRenderer()),
	)
	vulnDoc := new(bytes.Buffer)
	i := item.(map[string]interface{})
	contentText := i["content_text"].(string)
	amendedDoc := AmendCveDoc(contentText)
	err := gm.Convert([]byte(amendedDoc), vulnDoc)
	if err != nil {
		return nil, err
	}
	var c Content
	err = json.Unmarshal(vulnDoc.Bytes(), &c)
	if err != nil {
		return nil, err
	}
	severity, score := utils.CvssVectorToScore(c.Cvss)
	vulnerability := Vulnerability{
		ID:               mid,
		Summary:          i["summary"].(string),
		Urls:             []string{i["url"].(string), i["external_url"].(string)},
		CreatedAt:        i["date_published"].(string),
		AffectedVersions: c.AffectedVersions,
		FixedVersions:    c.FixedVersions,
		Description:      c.Description,
		Component:        c.ComponentName,
		CvssV3:           Cvssv3{Vector: c.Cvss, Score: score},
	}
	if len(severity) > 0 {
		vulnerability.Severity = severity
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

func AmendCveDoc(doc string) string {
	var lineWriter bytes.Buffer
	docReader := strings.NewReader(doc)
	fileScanner := bufio.NewScanner(docReader)
	fileScanner.Split(bufio.ScanLines)
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
			lineWriter.WriteString(fmt.Sprintf("%s\n", line))
			continue
		}
		// complete version parsing
		if utils.MatchRegEx(header, line) && !strings.Contains(strings.ToLower(line), "fixed versions") && startFixed {
			endFixed = true
		}

		if len(strings.TrimSpace(line)) == 0 {
			continue
		}
		vp, sign := utils.VersionParts(line)
		if len(vp) > 0 {
			line = utils.UpdatedLine(vp, sign)
			lineWriter.WriteString(fmt.Sprintf("%s\n", line))
			continue
		}
	}
	return lineWriter.String()
}

func ValidateCveData(cves []*Vulnerability) error {
	var result error
	for _, cve := range cves {
		newCve := isNewCve(cve.ID)
		if len(cve.ID) == 0 {
			result = multierror.Append(result, fmt.Errorf("\nid is mssing on cve #%s", cve.ID))
		}
		if len(cve.CreatedAt) == 0 {
			result = multierror.Append(result, fmt.Errorf("\nCreatedAt is mssing on cve #%s", cve.ID))
		}
		if len(cve.Summary) == 0 {
			result = multierror.Append(result, fmt.Errorf("\nSummary is mssing on cve #%s", cve.ID))
		}
		if newCve && len(strings.TrimPrefix(cve.Component, upstreamRepoByName(cve.Component))) == 0 {
			result = multierror.Append(result, fmt.Errorf("\nComponent is mssing on cve #%s", cve.ID))
		}
		if newCve && len(cve.Description) == 0 {
			result = multierror.Append(result, fmt.Errorf("\nDescription is mssing on cve #%s", cve.ID))
		}
		if newCve && len(cve.AffectedVersions) == 0 {
			result = multierror.Append(result, fmt.Errorf("\nFixedVersion is missing on cve #%s", cve.ID))
		}
		if newCve && len(cve.AffectedVersions) > 0 {
			for _, v := range cve.AffectedVersions {
				_, err := version.Parse(v.Introduced)
				if err != nil {
					result = multierror.Append(result, fmt.Errorf("\nAffectedVersion From %s is invalid on cve #%s", v.Introduced, cve.ID))
				}
			}
		}

		if newCve && len(cve.FixedVersions) == 0 {
			result = multierror.Append(result, fmt.Errorf("\nFixedVersion is missing on cve #%s", cve.ID))
		}

		if newCve && len(cve.FixedVersions) > 0 {
			for _, v := range cve.FixedVersions {
				_, err := version.Parse(v.Fixed)
				if err != nil {
					result = multierror.Append(result, fmt.Errorf("\nFixedVersion Fixed %s is invalid on cve #%s", v.Introduced, cve.ID))
				}
			}
		}
		if len(cve.Urls) == 0 {
			result = multierror.Append(result, fmt.Errorf("\nUrls is mssing on cve #%s", cve.ID))
		}
	}
	return result
}

func isNewCve(cveID string) bool {
	cveParts := strings.Split(cveID, "-")
	if len(cveParts) > 1 {
		if cveParts[0] != "CVE" {
			return false
		}
		if year, err := strconv.Atoi(cveParts[1]); err == nil {
			return year >= 2023
		}
	}
	return false
}

func upstreamRepoByName(component string) string {
	for key, components := range upstreamRepo {
		for _, c := range strings.Split(components, ",") {
			if strings.TrimSpace(c) == strings.ToLower(component) {
				return key
			}
		}
	}
	return ""
}
