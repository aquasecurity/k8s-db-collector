package cve

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/aquasecurity/k8s-db-collector/collectors/cvedb/utils"
)

const (
	k8svulnDBURL = "https://kubernetes.io/docs/reference/issues-security/official-cve-feed/index.json"
	mitreURL     = "https://cveawg.mitre.org/api/cve"
	cveList      = "https://www.cve.org/"
	semver       = "SEMVER"
)

func Collect() (*K8sVulnDB, error) {
	response, err := http.Get(k8svulnDBURL)
	if err != nil {
		return nil, err
	}
	vulnDB, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	return ParseVulnDBData(vulnDB)
}

type MitreCVE struct {
	CveMetadata CveMetadata
	Containers  Containers
}

type Containers struct {
	Cna struct {
		Affected []struct {
			Product  string
			Vendor   string
			Versions []struct {
				Status          string
				Version         string
				LessThanOrEqual string
				LessThan        string
			}
		}
		Descriptions []struct {
			Value string
		}
	}
}

type CveMetadata struct {
	CveId string
}

func LoadCveFromMitre(externalURL string, cveID string) (*Vulnerability, error) {
	currentVuln := &Vulnerability{}
	if strings.HasPrefix(externalURL, cveList) {
		response, err := http.Get(fmt.Sprintf("%s/%s", mitreURL, cveID))
		if err == nil {
			cveInfo, err := io.ReadAll(response.Body)
			if err == nil {
				var cve MitreCVE
				err = json.Unmarshal(cveInfo, &cve)
				if err == nil {
					versions := make([]*Version, 0)
					var component string
					for _, a := range cve.Containers.Cna.Affected {
						if len(component) == 0 {
							component = a.Product
						}
						for _, v := range a.Versions {
							if v.Status == "affected" {
								var to, fixed string
								origFrom := v.Version
								from := v.Version
								if origFrom == "0" {
									from = "0.0.0"
								}
								switch {
								case origFrom == "unspecified" && len(strings.TrimSpace(v.LessThanOrEqual)) > 0:
									to, _ = utils.ExtractVersions(utils.TrimString(v.LessThanOrEqual, []string{"v", "V"}))
									from = strings.TrimSpace(fmt.Sprintf("%s.%s", to[:strings.LastIndex(to, ".")], "0"))
								case origFrom == "unspecified" && len(strings.TrimSpace(v.LessThan)) > 0:
									tempFrom := utils.TrimString(v.LessThan, []string{"v", "V"})
									from = strings.TrimSpace(fmt.Sprintf("%s.%s", tempFrom[:strings.LastIndex(tempFrom, ".")], "0"))
									fixed = tempFrom
								case strings.HasPrefix(strings.TrimSpace(origFrom), "prior to"):
									fixed = strings.TrimSpace(strings.TrimPrefix(origFrom, "prior to"))
									from = utils.TrimString(fixed, []string{"v", "V"})
									from = strings.TrimSpace(fmt.Sprintf("%s.%s", from[:strings.LastIndex(from, ".")], "0"))
								case strings.HasSuffix(strings.TrimSpace(origFrom), ".x"):
									from = utils.TrimString(origFrom, []string{"v", "V"})
									from = strings.TrimSpace(fmt.Sprintf("%s.%s", from[:strings.LastIndex(from, ".")], "0"))
									to = from
								default:
									from, to = utils.ExtractVersions(utils.TrimString(from, []string{"v", "V"}))
								}
								if strings.Count(from, ".") == 1 || strings.Count(to, ".") == 1 {
									continue
								}
								ver := &Version{Introduced: from, Fixed: fixed, LastAffected: to}
								versions = append(versions, ver)

							}
						}
					}
					currentVuln.Component = component
					if len(cve.Containers.Cna.Descriptions) > 0 {
						currentVuln.Description = cve.Containers.Cna.Descriptions[0].Value
					}
					currentVuln.AffectedVersions = versions
				}
			}
		}
		if currentVuln.Component == "kubernetes" {
			if v := getComponentFromDescription(currentVuln.Description); v != "" {
				currentVuln.Component = v
			}
		}
	}
	return currentVuln, nil
}

func ParseVulnDBData(vulnDB []byte) (*K8sVulnDB, error) {
	var db map[string]interface{}
	err := json.Unmarshal(vulnDB, &db)
	if err != nil {
		return nil, err
	}
	fullVulnerabilities := make([]*Vulnerability, 0)
	for _, item := range db["items"].([]interface{}) {
		i := item.(map[string]interface{})
		externalURL := i["external_url"].(string)
		id := i["id"].(string)
		for _, cveID := range getMultiIDs(id) {
			currentVuln, err := LoadCveFromMitre(externalURL, cveID)
			if err != nil {
				fmt.Printf("failed to load cve %s data from mitre", cveID)
			}
			vuln, err := ParseVulnItem(item, cveID)
			if err != nil {
				return nil, err
			}
			if len(vuln.Component) == 0 || strings.Contains(currentVuln.Component, "n/a") {
				continue
			}
			upstreamPrefix := upstreamOrgByName(strings.TrimPrefix(vuln.Component, "kube-"))
			if upstreamPrefix != "" {
				vuln.Component = strings.ToLower(fmt.Sprintf("%s/%s", upstreamPrefix, upstreamRepoByName(strings.TrimPrefix(vuln.Component, "kube-"))))
			} else {
				av := upstreamOrgByName(strings.TrimPrefix(currentVuln.Component, "kube-"))
				vuln.Component = strings.ToLower(fmt.Sprintf("%s/%s", av, upstreamRepoByName(strings.TrimPrefix(currentVuln.Component, "kube-"))))
			}
			if len(currentVuln.Description) > 0 {
				vuln.Description = currentVuln.Description
			}
			updateVulns(currentVuln, vuln)
			if len(currentVuln.AffectedVersions) > 0 {
				vuln.AffectedVersions = currentVuln.AffectedVersions
			}
			updateAffectedEvents(vuln)
			fullVulnerabilities = append(fullVulnerabilities, vuln)
		}
	}
	err = ValidateCveData(fullVulnerabilities)
	if err != nil {
		return nil, err
	}
	return &K8sVulnDB{fullVulnerabilities}, nil
}

func updateVulns(currVuln *Vulnerability, tc *Vulnerability) {
	tempMap := make(map[string]*Version)
	versionZeroFixed := make([]string, 0)
	for index, v := range tc.AffectedVersions {
		if len(tc.FixedVersions) > index {
			v.Fixed = tc.FixedVersions[index].Fixed
			if v.Introduced != "0.0.0" {
				tempMap[v.Introduced] = v
			} else {
				versionZeroFixed = append(versionZeroFixed, v.Fixed)
			}
		}
	}
	fixedVersionIndex := 0
	for _, v := range currVuln.AffectedVersions {
		if v.Introduced == "0.0.0" {
			if len(versionZeroFixed) > fixedVersionIndex {
				v.Fixed = versionZeroFixed[fixedVersionIndex]
				fixedVersionIndex++
			}
		} else {
			if val, ok := tempMap[v.Introduced]; ok {
				v.Fixed = val.Fixed
			}
		}
	}
}

func updateAffectedEvents(v *Vulnerability) {
	for _, av := range v.AffectedVersions {
		if len(av.Introduced) == 0 {
			continue
		}
		if av.Introduced == "0.0.0" {
			av.Introduced = "0"
		}
		events := make([]*Event, 0)
		ranges := make([]*Range, 0)
		if len(av.Introduced) > 0 {
			events = append(events, &Event{Introduced: av.Introduced})
		}
		if len(av.Fixed) > 0 {
			events = append(events, &Event{Fixed: av.Fixed})
		}
		if len(av.LastAffected) > 0 {
			events = append(events, &Event{LastAffected: av.LastAffected})
		}
		ranges = append(ranges, &Range{
			RangeType: semver,
			Events:    events,
		})
		v.Affected = append(v.Affected, &Affected{Ranges: ranges})
	}
}
