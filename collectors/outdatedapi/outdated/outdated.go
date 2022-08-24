package outdated

import (
	"fmt"
	"strings"
)

//OutdatedAPI object
type OutdatedAPI struct {
	Description string
	Deprecated  string
	Removed     string
	Gav         Gvk
}

//Gvk group/version/kind object
type Gvk struct {
	Group   string `json:"group"`
	Version string `json:"version"`
	Kind    string `json:"kind"`
}

//K8sAPI object
type K8sAPI struct {
	Description        string `json:"description,omitempty"`
	DeprecatedVersion  string `json:"deprecated-version"`
	ReplacementVersion string `json:"replacement-api"`
	RemovedVersion     string `json:"removed-version"`
	Group              string `json:"group"`
	Version            string `json:"version"`
	Kind               string `json:"kind"`
	Ref                string `json:"ref"`
}

//MergeMdSwaggerVersions merge swagger and marjdown collectors results
func MergeMdSwaggerVersions(objs []*OutdatedAPI, mDetails map[string]*OutdatedAPI) []K8sAPI {
	apis := make([]K8sAPI, 0)

	for _, obj := range objs {
		definition := strings.TrimSpace(fmt.Sprintf("%s.%s.%s", obj.Gav.Group, obj.Gav.Version, obj.Gav.Kind))
		if val, ok := mDetails[fmt.Sprintf("io.k8s.api.%s", definition)]; ok {
			val.Removed = obj.Removed
			continue
		}
		apis = append(apis, K8sAPI{Description: obj.Description, Group: obj.Gav.Group, Version: obj.Gav.Version, Kind: obj.Gav.Kind, DeprecatedVersion: obj.Deprecated, RemovedVersion: obj.Removed})
	}
	for _, md := range mDetails {
		apis = append(apis, K8sAPI{Description: md.Description, Group: md.Gav.Group, Version: md.Gav.Version, Kind: md.Gav.Kind, DeprecatedVersion: md.Deprecated, RemovedVersion: md.Removed})
	}
	return apis
}

//ValidateOutdatedAPI validate outdated data is complete
func ValidateOutdatedAPI(K8sapis map[string]map[string]map[string]string) (map[string]map[string]map[string]string, error) {
	for _, ka := range K8sapis {
		if len(ka) == 0 {
			return nil, fmt.Errorf("failed to get outdated API missing Version or Kind or Group")
		}
		for _, pa := range ka {
			if len(pa) == 0 {
				return nil, fmt.Errorf("failed to get outdated API missing Version or Kind or Group")
			}
		}
	}
	return K8sapis, nil
}
