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
	Description       string `json:"description"`
	DeprecatedVersion string `json:"deprecated-version"`
	RemovedVersion    string `json:"removed-version"`
	Group             string `json:"group"`
	Version           string `json:"version"`
	Kind              string `json:"kind"`
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

//ValidateOutDatedAPI validate outdated data is complete
func ValidateOutDatedAPI(K8sapis []K8sAPI) []K8sAPI {
	apis := make([]K8sAPI, 0)
	for _, ka := range K8sapis {
		if len(ka.Version) == 0 || len(ka.Kind) == 0 || len(ka.Group) == 0 {
			continue
		}
		if !validVersion(ka.DeprecatedVersion) {
			ka.DeprecatedVersion = ""
		}
		if !validVersion(ka.RemovedVersion) {
			ka.RemovedVersion = ""
		}
		if len(ka.DeprecatedVersion) == 0 && len(ka.RemovedVersion) == 0 {
			continue
		}
		if len(ka.Description) == 0 {
			continue
		}
		apis = append(apis, ka)
	}
	return apis
}

func validVersion(version string) bool {
	return len(version) != 0 && strings.HasPrefix(version, "v")
}
