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
					if cve.CveMetadata.CveId == "CVE-2020-8566" {
						fmt.Println("here")
					}
					for _, a := range cve.Containers.Cna.Affected {
						if len(component) == 0 {
							if a.Product == a.Vendor {
								component = fmt.Sprintf("%s/%s", strings.ToLower(a.Vendor), strings.ToLower(a.Product))
							} else {
								component = a.Product
							}
						}
						for _, v := range a.Versions {
							if v.Status == "affected" {
								var to, fixed string
								origFrom := v.Version
								from := v.Version
								if origFrom == "0" {
									from = "0.0.0"
								}
								if origFrom == "unspecified" && len(strings.TrimSpace(v.LessThanOrEqual)) > 0 {
									to, _ = utils.ExtractVersions(utils.TrimString(v.LessThanOrEqual, []string{"v", "V"}))
									from = strings.TrimSpace(fmt.Sprintf("%s.%s", to[:strings.LastIndex(to, ".")], "0"))
								} else if origFrom == "unspecified" && len(strings.TrimSpace(v.LessThan)) > 0 {
									tempFrom := utils.TrimString(v.LessThan, []string{"v", "V"})
									from = strings.TrimSpace(fmt.Sprintf("%s.%s", tempFrom[:strings.LastIndex(tempFrom, ".")], "0"))
									fixed = tempFrom
								} else {
									from, to = utils.ExtractVersions(utils.TrimString(from, []string{"v", "V"}))
								}
								ver := &Version{Introduced: from}
								if len(to) > 0 {
									to = utils.FindVersion(to)
									ver.LastAffected = to
								}
								if len(fixed) > 0 {
									ver.Fixed = fixed
								}
								versions = append(versions, ver)
							}
						}
					}
					currentVuln.Component = component
					if len(cve.Containers.Cna.Descriptions) > 0 {
						currentVuln.Description = cve.Containers.Cna.Descriptions[0].Value
					}
					currentVuln.AffectedVersion = versions
				}
			}
		}
		if currentVuln.Component == "kubernetes/kubernetes" {
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
			if av := upstreamRepoByName(strings.TrimPrefix(vuln.Component, "kube-")); av == "" {
				vuln.Component = fmt.Sprintf("%s/%s", upstreamRepoByName(strings.TrimPrefix(currentVuln.Component, "kube-")), strings.TrimPrefix(currentVuln.Component, "kube-"))
			} else {
				vuln.Component = fmt.Sprintf("%s/%s", av, strings.TrimPrefix(currentVuln.Component, "kube-"))
			}
			if len(currentVuln.Description) > 0 {
				vuln.Description = currentVuln.Description
			}
			updateVulns(currentVuln, vuln)
			if len(currentVuln.AffectedVersion) > 0 {
				vuln.AffectedVersion = currentVuln.AffectedVersion
			}
			fullVulnerabilities = append(fullVulnerabilities, vuln)
		}
	}
	/*err = ValidateCveData(fullVulnerabilities)
	if err != nil {
		return nil, err
	}*/
	return &K8sVulnDB{fullVulnerabilities}, nil
}

func updateVulns(currVuln *Vulnerability, tc *Vulnerability) {
	tempMap := make(map[string]*Version)
	versionZeroFixed := make([]string, 0)
	for index, v := range tc.AffectedVersion {
		if len(tc.FixedVersion) > index {
			v.Fixed = tc.FixedVersion[index].Fixed
			if v.Introduced != "0.0.0" {
				tempMap[v.Introduced] = v
			} else {
				versionZeroFixed = append(versionZeroFixed, v.Fixed)
			}
		}
	}
	fixedVersionIndex := 0
	for _, v := range currVuln.AffectedVersion {
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
