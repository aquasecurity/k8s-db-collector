package collector

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
	API               string `header:"k8s api"`
	DeprecatedVersion string `header:"deprecated Version"`
	RemovedVersion    string `header:"removed Version"`
}

//MergeMdSwaggerVersions merge swagger and marjdown collector results
func MergeMdSwaggerVersions(objs []*OutdatedAPI, mDetails map[string]*OutdatedAPI) []K8sAPI {
	apis := make([]K8sAPI, 0)

	for _, obj := range objs {
		definition := strings.TrimSpace(fmt.Sprintf("%s.%s.%s", obj.Gav.Group, obj.Gav.Version, obj.Gav.Kind))
		if val, ok := mDetails[fmt.Sprintf("io.k8s.api.%s", definition)]; ok {
			val.Removed = obj.Removed
			continue
		}
		apis = append(apis, K8sAPI{API: fmt.Sprintf("%s.%s.%s", obj.Gav.Group, obj.Gav.Version, obj.Gav.Kind), DeprecatedVersion: obj.Deprecated, RemovedVersion: obj.Removed})
	}
	for _, md := range mDetails {
		apis = append(apis, K8sAPI{API: fmt.Sprintf("%s.%s.%s", md.Gav.Group, md.Gav.Version, md.Gav.Kind), DeprecatedVersion: md.Deprecated, RemovedVersion: md.Removed})
	}
	return apis
}
