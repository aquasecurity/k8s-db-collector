package cve

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/aquasecurity/k8s-db-collector/collectors/cvedb/utils"
	"github.com/hashicorp/go-version"
)

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
		Descriptions []Descriptions
		Metrics      []struct {
			CvssV3_1 struct {
				VectorString string
			}
			CvssV3_0 struct {
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

type Descriptions struct {
	Lang  string
	Value string
}

func parseMitreCve(externalURL string, cveID string) (*Vulnerability, error) {
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
		var requireMerge bool
		for _, a := range cve.Containers.Cna.Affected {
			if len(component) == 0 {
				component = strings.ToLower(a.Product)
			}
			for _, sv := range a.Versions {
				if sv.Status == "affected" {
					var introduce, lastAffected, fixed string
					v, ok := sanitizedVersion(sv)
					if !ok {
						continue
					}
					switch {
					case len(strings.TrimSpace(v.LessThanOrEqual)) > 0:
						introduce, lastAffected = utils.ExtractVersions(v.LessThanOrEqual, v.Version, true)
					case len(strings.TrimSpace(v.LessThan)) > 0:
						introduce, lastAffected = utils.ExtractVersions(v.LessThan, v.Version, false)
						fixed = v.LessThan
					case utils.MajorVersion(v.Version):
						requireMerge = true
						introduce = v.Version
					default:
						introduce, lastAffected = utils.ExtractRangeVersions(v.Version)
					}
					ver := &Version{Introduced: introduce, Fixed: fixed, LastAffected: lastAffected}
					versions = append(versions, ver)
				}
			}
		}
		vulnerableVersions := versions
		if requireMerge {
			vulnerableVersions, err = mergeVersionRange(versions)
			if err != nil {
				return nil, err
			}
		}
		vector, severity, score := getMetrics(cve)
		description := getDescription(cve.Containers.Cna.Descriptions)
		component = utils.GetComponentFromDescription(description, component)

		return &Vulnerability{
			Component:        component,
			Description:      description,
			AffectedVersions: vulnerableVersions,
			CvssV3: Cvssv3{
				Vector: vector,
				Score:  score,
			},
			Severity: severity,
		}, nil
	}
	return nil, fmt.Errorf("unsupported external url %s", externalURL)
}

func sanitizedVersion(v *MitreVersion) (*MitreVersion, bool) {
	if strings.Contains(v.Version, "n/a") && len(v.LessThan) == 0 && len(v.LessThanOrEqual) == 0 {
		return v, false
	}
	if (v.LessThanOrEqual == "unspecified" || v.LessThan == "unspecified") && len(v.Version) > 0 {
		return v, false
	}
	if len(v.LessThanOrEqual) > 0 {
		if v.LessThanOrEqual == "<=" {
			v.LessThanOrEqual = v.Version
		} else if strings.Contains(v.LessThanOrEqual, "<=") {
			v.LessThanOrEqual = strings.TrimSpace(strings.ReplaceAll(strings.TrimSpace(v.LessThanOrEqual), "<=", ""))
		}
	}
	if len(v.LessThan) > 0 {
		if strings.HasPrefix(strings.TrimSpace(v.LessThan), "prior to") {
			v.LessThan = strings.TrimSpace(strings.TrimPrefix(v.Version, "prior to"))
		} else if strings.HasSuffix(strings.TrimSpace(v.LessThan), "*") {
			v.Version = strings.TrimSpace(strings.ReplaceAll(v.LessThan, "*", ""))
			v.LessThan = ""
		}
	}

	if len(v.Version) > 0 {
		if strings.HasPrefix(v.Version, "< ") {
			v.LessThan = strings.TrimPrefix(v.Version, "< ")
		} else if strings.HasPrefix(v.Version, "<= ") {
			v.LessThanOrEqual = strings.TrimPrefix(v.Version, "<= ")
		} else if strings.HasPrefix(strings.TrimSpace(v.Version), "prior to") {
			priorToVersion := strings.TrimSpace(strings.TrimPrefix(v.Version, "prior to"))
			if utils.MajorVersion(priorToVersion) {
				priorToVersion = priorToVersion + ".0"
				v.Version = priorToVersion
			}
			v.LessThan = priorToVersion
		} else if strings.HasSuffix(strings.TrimSpace(v.Version), ".x") {
			li := strings.LastIndex(v.Version, ".")
			if li != -1 {
				v.Version = strings.TrimSpace(fmt.Sprintf("%s%s", v.Version[:li], ""))
			}
		}
	}

	if strings.HasSuffix(v.LessThan, ".0") {
		v.Version = "0"
	}

	return &MitreVersion{
		Version:         utils.TrimString(v.Version, []string{"v", "V"}),
		LessThanOrEqual: utils.TrimString(v.LessThanOrEqual, []string{"v", "V"}),
		LessThan:        utils.TrimString(v.LessThan, []string{"v", "V"}),
	}, true
}

func getDescription(descriptions []Descriptions) string {
	for _, d := range descriptions {
		if d.Lang == "en" {
			return d.Value
		}
	}
	return ""
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

func mergeVersionRange(affectedVersions []*Version) ([]*Version, error) {
	// this special handling is made to handle to case of conceutive vulnable major versions example:
	// vulnerable 1.3, 1.4, 1.5, 1.6 and prior to versions 1.7.14, 1.8.9 will be form as follow:
	// Introduced: 1.3.0  LastAffected: 1.7.0
	// Introduced: 1.7.0  Fixed: 1.7.14
	// Introduced: 1.8.0  Fixed: 1.8.9

	newAffectedVesion := make([]*Version, 0)
	sort.Sort(byVersion(affectedVersions))
	var firstMajorVersion, lastMajorVersion string
	for _, av := range affectedVersions {
		if len(firstMajorVersion) == 0 && utils.MajorVersion(av.Introduced) {
			firstMajorVersion = av.Introduced
			continue
		}
		if strings.Count(av.Introduced, ".") > 1 && len(firstMajorVersion) > 0 {
			lastMajorVersion = av.Introduced
			newAffectedVesion = append(newAffectedVesion, &Version{Introduced: fmt.Sprintf("%s.0", firstMajorVersion), LastAffected: lastMajorVersion})
			newAffectedVesion = append(newAffectedVesion, &Version{Introduced: av.Introduced, LastAffected: av.LastAffected, Fixed: av.Fixed})
			firstMajorVersion = ""
			continue
		}
		if len(lastMajorVersion) > 0 || len(firstMajorVersion) == 0 {
			newAffectedVesion = append(newAffectedVesion, av)
			lastMajorVersion = ""
		}
	}

	// this special handling is made to handle to case of conceutive vulnable major versions where no fixed version is provided example:
	// vulnerable 1.3, 1.4, 1.5, 1.6  will be form as follow:
	// Introduced: 1.3.0  Fixed: 1.7.0
	if lastMajorVersion == "" && utils.MajorVersion(firstMajorVersion) {
		ver, err := version.NewSemver(affectedVersions[len(affectedVersions)-1].Introduced + ".0")
		if err != nil {
			return nil, err
		}
		versionParts := ver.Segments()
		if len(versionParts) == 3 {
			fixed := fmt.Sprintf("%d.%d.%d", versionParts[0], versionParts[1]+1, versionParts[2])
			newAffectedVesion = append(newAffectedVesion, &Version{Introduced: fmt.Sprintf("%s.0", firstMajorVersion), Fixed: fixed})
		}
	}
	return newAffectedVesion, nil
}

func getMetrics(cve MitreCVE) (string, string, float64) {
	var vectorString, severity string
	var score float64
	for _, metric := range cve.Containers.Cna.Metrics {
		vectorString = metric.CvssV3_0.VectorString
		if len(vectorString) == 0 {
			vectorString = metric.CvssV3_1.VectorString
		}
		severity, score = utils.CvssVectorToScore(vectorString)
	}
	return vectorString, severity, score
}
