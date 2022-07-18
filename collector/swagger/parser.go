package swagger

import (
	"encoding/json"
	"fmt"
	"github.com/hashicorp/go-version"
	"k8s-outdated/collector"
	"net/http"
	"strings"
)

const (
	k8sTagsURL = "https://api.github.com/repos/kubernetes/kubernetes/git/refs/tags"
	baseURL    = "https://raw.githubusercontent.com/kubernetes/kubernetes"
	fileURL    = "api/openapi-spec/swagger.json"

	servedIn     = "served in"
	removedIn    = "removal in"
	deprecatedIn = "deprecated in"
)

//Reference version ref object
type Reference struct {
	Ref    string `json:"ref"`
	NodeID string `json:"node_id"`
	URL    string `json:"url"`
}

//OpenAPISpec open api spec object
type OpenAPISpec struct {
}

//NewOpenAPISpec construct a new OpenAPISpec object
func NewOpenAPISpec() *OpenAPISpec {
	return &OpenAPISpec{}
}

//CollectOutdatedAPI collect removed api version from k8s swagger api
func (vc OpenAPISpec) CollectOutdatedAPI(k8sVer string) (map[string]*collector.OutdatedAPI, error) {
	r, err := http.Get(k8sTagsURL)
	if err != nil {
		return nil, err
	}
	var refs []Reference
	err = json.NewDecoder(r.Body).Decode(&refs)
	if err != nil {
		return nil, err
	}
	v1, err := version.NewVersion(k8sVer)
	if err != nil {
		return nil, err
	}
	kVer, err := vc.getMatchingVersions(refs, err, v1)
	if err != nil {
		return nil, err
	}
	vList, err := vc.fetchSwaggerVersions(kVer)
	if err != nil {
		return nil, err
	}
	return vc.versionToDetails(vList)
}

func (vc OpenAPISpec) getMatchingVersions(refs []Reference, err error, v1 *version.Version) ([]string, error) {
	kVer := make([]string, 0)
	for _, r := range refs {
		if strings.Contains(r.Ref, "-rc") ||
			strings.Contains(r.Ref, "-alpha") ||
			strings.Contains(r.Ref, "-beta") {
			continue
		}
		v := strings.Replace(r.Ref, "refs/tags/", "", -1)
		v2, newVerErr := version.NewVersion(strings.Replace(v, "v", "", -1))
		if newVerErr != nil {
			return nil, err
		}
		if v1.LessThanOrEqual(v2) {
			kVer = append(kVer, v)
		}
	}
	return kVer, nil
}

//gosec -exclude=G303
func (vc OpenAPISpec) fetchSwaggerVersions(versions []string) ([]map[string]interface{}, error) {
	swaggerVersionsData := make([]map[string]interface{}, 0)
	for _, kv := range versions {
		res, err := http.Get(buildSwaggerURL(kv))
		if err != nil {
			return nil, err
		}
		var apiMap map[string]interface{}
		err = json.NewDecoder(res.Body).Decode(&apiMap)
		if err != nil {
			return nil, err
		}
		swaggerVersionsData = append(swaggerVersionsData, apiMap)
	}
	return swaggerVersionsData, nil
}

func buildSwaggerURL(version string) string {
	return fmt.Sprintf("%s/%s/%s", baseURL, version, fileURL)
}

func (vc OpenAPISpec) versionToDetails(swaggerData []map[string]interface{}) (map[string]*collector.OutdatedAPI, error) {
	if len(swaggerData) == 0 {
		return map[string]*collector.OutdatedAPI{}, nil
	}
	gavMap := make(map[string]*collector.OutdatedAPI)
	for _, data := range swaggerData {
		p, ok := data["definitions"]
		if !ok {
			return map[string]*collector.OutdatedAPI{}, nil
		}
		m, err := vc.findOutDatedAPIVersion(p, gavMap)
		if err != nil {
			return m, err
		}
	}
	return gavMap, nil
}

func (vc OpenAPISpec) findOutDatedAPIVersion(p interface{}, gavMap map[string]*collector.OutdatedAPI) (map[string]*collector.OutdatedAPI, error) {
	for key, val := range p.(map[string]interface{}) {
		mval, ok := val.(map[string]interface{})
		if !ok {
			continue
		}
		gav, ok := mval["x-kubernetes-group-version-kind"]
		if !ok {
			continue
		}
		ga, err := vc.parseSwaggerData(gav)
		if err != nil {
			return nil, err
		}
		if len(ga) == 0 {
			continue
		}
		desc, ok := mval["description"].(string)
		if !ok {
			continue
		}
		dep, rem := vc.depRemovedVersion(desc)
		object := collector.OutdatedAPI{Description: desc, Gav: ga[0], Deprecated: dep, Removed: rem}
		if vc.isOutdatedAPIDataIncomplete(object) {
			continue
		}
		gavMap[key] = &object
	}
	return nil, nil
}

func (vc OpenAPISpec) isOutdatedAPIDataIncomplete(object collector.OutdatedAPI) bool {
	return (len(object.Deprecated) == 0 && len(object.Removed) == 0) || len(object.Gav.Kind) == 0 || len(object.Gav.Version) == 0 || len(object.Gav.Group) == 0
}

func (vc OpenAPISpec) parseSwaggerData(gav interface{}) ([]collector.Gvk, error) {
	b, err := json.Marshal(&gav)
	if err != nil {
		return nil, err
	}
	var ga []collector.Gvk
	err = json.Unmarshal(b, &ga)
	if err != nil {
		return nil, err
	}
	return ga, nil
}

func (vc OpenAPISpec) depRemovedVersion(desc string) (string, string) {
	var dep, rem string
	lower := strings.ToLower(desc)
	if strings.Contains(lower, deprecatedIn) {
		dep = collector.FindRemovedDeprecatedVersion(lower, deprecatedIn)
	}
	if strings.Contains(lower, removedIn) {
		rem = collector.FindRemovedDeprecatedVersion(lower, removedIn)
	}
	if strings.Contains(lower, servedIn) {
		rem = collector.FindRemovedDeprecatedVersion(lower, servedIn)
	}
	return dep, rem
}
