package cve

import (
	"encoding/json"
	"fmt"
	"github.com/hashicorp/go-version"
	"io"
	"net/http"
	"sort"
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
			Versions []*MitreVersion
		}
		Descriptions []struct {
			Value string
		}
		Metrics []struct {
			CvssV3_1 struct {
				VectorString string
			}
		}
	}
}

type MitreVersion struct {
	Status          string
	Version         string
	LessThanOrEqual string
	LessThan        string
	VersionType     string
}

type CveMetadata struct {
	CveId string
}

func parseMitreCve(externalURL string, cveID string) (*Vulnerability, error) {
	currentVuln := &Vulnerability{}
	if strings.HasPrefix(externalURL, cveList) {
		var cve MitreCVE
		response, err := http.Get(fmt.Sprintf("%s/%s", mitreURL, cveID))
		if err != nil {
			return nil, err
		}
		cveInfo, err := io.ReadAll(response.Body)
		if err != nil {
			return nil, err
		}
		err = json.Unmarshal(cveInfo, &cve)
		if err != nil {
			return nil, err
		}
		versions := make([]*Version, 0)
		var component string
		for _, a := range cve.Containers.Cna.Affected {
			if len(component) == 0 {
				component = a.Product
			}
			for _, sv := range a.Versions {
				if sv.Status == "affected" {
					var from, to, fixed string
					v, ok := sanitizedVersion(sv)
					if !ok {
						continue
					}
					switch {
					case len(strings.TrimSpace(v.LessThanOrEqual)) > 0:
						from, to = utils.ExtractVersions(v.LessThanOrEqual, v.Version, "lessThenEqual")
					case len(strings.TrimSpace(v.LessThan)) > 0:
						from, to = utils.ExtractVersions(v.LessThan, v.Version, "lessThen")
						if strings.HasSuffix(v.LessThan, ".0") {
							from = "0"
						}
						fixed = v.LessThan
					default:
						if strings.Count(v.Version, ".") == 1 {
							currentVuln.MajorVersion = true
							from = v.Version
						} else {
							from, to = utils.ExtractVersions("", v.Version, "")
						}
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
		if len(cve.Containers.Cna.Metrics) > 0 {
			secerity, score := utils.CvssVectorToScore(cve.Containers.Cna.Metrics[0].CvssV3_1.VectorString)
			currentVuln.CvssV3 = Cvssv3{
				Vector: cve.Containers.Cna.Metrics[0].CvssV3_1.VectorString,
				Score:  score,
			}
			currentVuln.Severity = secerity
		}
		if strings.ToLower(currentVuln.Component) == "kubernetes" {
			if v := getComponentFromDescriptionAndffected(currentVuln.Description); v != "" {
				currentVuln.Component = v
			}
		}
	}
	return currentVuln, nil
}

const (
	// Kubernetes is a container orchestration system for Docker containers
	excludeNonCoreComponentsCves = "CVE-2019-11255,CVE-2020-10749,CVE-2020-8554"
)

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
		if strings.Contains(excludeNonCoreComponentsCves, id) {
			continue
		}
		for _, cveID := range getMultiIDs(id) {
			mitreCve, err := parseMitreCve(externalURL, cveID)
			if err != nil || len(mitreCve.Component) == 0 {
				continue
			}
			officialK8sCve, err := parseOfficialK8sCve(item, cveID)
			if err != nil {
				return nil, err
			}
			if len(mitreCve.AffectedVersions) == 0 {
				continue
			}
			officialK8sCve.Component = getComponentName(officialK8sCve, mitreCve)
			if len(mitreCve.Description) > 0 {
				officialK8sCve.Description = mitreCve.Description
			}
			officialK8sCve.AffectedVersions = mitreCve.AffectedVersions
			if mitreCve.MajorVersion {
				officialK8sCve.MajorVersion = true
			}
			updateAffectedEvents(officialK8sCve)
			fullVulnerabilities = append(fullVulnerabilities, officialK8sCve)
		}
	}
	err = ValidateCveData(fullVulnerabilities)
	if err != nil {
		return nil, err
	}
	return &K8sVulnDB{fullVulnerabilities}, nil
}

type byVersion []*Version

func (s byVersion) Len() int {
	return len(s)
}

func (s byVersion) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (s byVersion) Less(i, j int) bool {
	v1, err := version.NewVersion(s[i].Introduced)
	if err != nil {
		return false
	}
	v2, err := version.NewVersion(s[j].Introduced)
	if err != nil {
		return false
	}
	return v1.LessThan(v2)
}

func updateAffectedEvents(v *Vulnerability) {
	if v.MajorVersion {
		newAffectedVesion := make([]*Version, 0)
		sort.Sort(byVersion(v.AffectedVersions))
		var startVersion, lastVersion string
		for _, av := range v.AffectedVersions {
			if len(startVersion) == 0 && strings.Count(av.Introduced, ".") == 1 {
				startVersion = av.Introduced
				continue
			}
			if strings.Count(av.Introduced, ".") > 1 && len(lastVersion) == 0 && len(startVersion) > 0 {
				lastVersion = av.Introduced
				newAffectedVesion = append(newAffectedVesion, &Version{Introduced: startVersion + ".0", LastAffected: lastVersion})
				newAffectedVesion = append(newAffectedVesion, &Version{Introduced: av.Introduced, LastAffected: av.LastAffected, Fixed: av.Fixed})
				startVersion = ""
				continue
			}
			if len(lastVersion) > 0 || len(startVersion) == 0 {
				newAffectedVesion = append(newAffectedVesion, av)
				lastVersion = ""
			}
		}
		if lastVersion == "" && strings.Count(startVersion, ".") == 1 {
			ver, err := version.NewSemver(v.AffectedVersions[len(v.AffectedVersions)-1].Introduced + ".0")
			if err == nil {
				versionParts := ver.Segments()
				if len(versionParts) == 3 {
					fixed := fmt.Sprintf("%d.%d.%d", versionParts[0], versionParts[1]+1, versionParts[2])
					newAffectedVesion = append(newAffectedVesion, &Version{Introduced: startVersion + ".0", Fixed: fixed})
				}
			}
		}
		v.AffectedVersions = newAffectedVesion
	}
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
		if len(av.LastAffected) > 0 && len(av.Fixed) == 0 {
			events = append(events, &Event{LastAffected: av.LastAffected})
		}
		if len(av.Introduced) > 0 && len(av.LastAffected) == 0 && len(av.Fixed) == 0 {
			events = append(events, &Event{LastAffected: av.Introduced})
		}
		ranges = append(ranges, &Range{
			RangeType: semver,
			Events:    events,
		})
		v.Affected = append(v.Affected, &Affected{Ranges: ranges})
	}
}

func sanitizedVersion(v *MitreVersion) (*MitreVersion, bool) {
	if strings.Contains(v.Version, "n/a") && len(v.LessThan) == 0 && len(v.LessThanOrEqual) == 0 {
		return v, false
	}
	if (v.LessThanOrEqual == "unspecified" || v.LessThan == "unspecified") && len(v.Version) > 0 {
		return v, false
	}
	if v.LessThanOrEqual == "<=" {
		v.LessThanOrEqual = v.Version
	}
	if strings.HasPrefix(v.Version, "< ") {
		v.LessThan = strings.TrimPrefix(v.Version, "< ")
	}
	if strings.HasPrefix(v.Version, "<= ") {
		v.LessThanOrEqual = strings.TrimPrefix(v.Version, "<= ")
	}
	if strings.HasPrefix(strings.TrimSpace(v.Version), "prior to") {
		priorToVersion := strings.TrimSpace(strings.TrimPrefix(v.Version, "prior to"))
		if strings.Count(priorToVersion, ".") == 1 {
			priorToVersion = priorToVersion + ".0"
		}
		v.LessThan = priorToVersion
		v.Version = priorToVersion
	}
	if strings.HasPrefix(strings.TrimSpace(v.LessThan), "prior to") {
		v.LessThan = strings.TrimSpace(strings.TrimPrefix(v.Version, "prior to"))
	}
	if strings.HasSuffix(strings.TrimSpace(v.LessThan), "*") {
		v.Version = strings.TrimSpace(strings.ReplaceAll(v.LessThan, "*", ""))
		v.LessThan = ""
	}
	if strings.HasSuffix(strings.TrimSpace(v.Version), ".x") {
		v.Version = strings.TrimSpace(fmt.Sprintf("%s%s", v.Version[:strings.LastIndex(v.Version, ".")], ""))
	}
	return &MitreVersion{
		Version:         utils.TrimString(v.Version, []string{"v", "V"}),
		LessThanOrEqual: utils.TrimString(v.LessThanOrEqual, []string{"v", "V"}),
		LessThan:        utils.TrimString(v.LessThan, []string{"v", "V"}),
	}, true
}

func getComponentName(officialK8sCve *Vulnerability, mitreCve *Vulnerability) string {
	// prefet mitre component if exists
	if len(mitreCve.Component) != 0 && strings.ToLower(mitreCve.Component) != "kubernetes" {
		officialK8sCve.Component = mitreCve.Component
	}
	officialK8sCve.CvssV3 = mitreCve.CvssV3
	officialK8sCve.Severity = mitreCve.Severity
	upstreamPrefix := upstreamOrgByName(strings.TrimPrefix(officialK8sCve.Component, "kube-"))
	if upstreamPrefix != "" {
		return strings.ToLower(fmt.Sprintf("%s/%s", upstreamPrefix, upstreamRepoByName(strings.TrimPrefix(officialK8sCve.Component, "kube-"))))
	}
	av := upstreamOrgByName(strings.TrimPrefix(mitreCve.Component, "kube-"))
	return strings.ToLower(fmt.Sprintf("%s/%s", av, upstreamRepoByName(strings.TrimPrefix(mitreCve.Component, "kube-"))))
}
