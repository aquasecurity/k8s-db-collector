package markdown

import (
	"bufio"
	"io"
	"k8s-outdated/collector"
	"net/http"
	"strings"
)

const (
	willNoLongerBeServed = "will no longer be served in"
	isNoLongerServedAsOf = "is no longer served as of"
	apiVersionOf         = "API version of"
	apiVersionsOf        = "API versions of"
	apiVersions          = "API version"
	theUpper             = "The"
	theLower             = "the"
	in                   = "in"
	and                  = "and"

	depGuide = "https://raw.githubusercontent.com/kubernetes/website/main/content/en/docs/reference/using-api/deprecation-guide.md"
)

//DeprecationGuide object
type DeprecationGuide struct {
}

//NewDeprecationGuide instansiate new DeprecationGuide
func NewDeprecationGuide() *DeprecationGuide {
	return &DeprecationGuide{}
}

//CollectOutdatedAPI collect removed api version from k8s deprecation guide
func (vz DeprecationGuide) CollectOutdatedAPI() ([]*collector.OutdatedAPI, error) {
	res, err := http.Get(depGuide)
	if err != nil {
		return nil, err
	}
	return vz.markdownToObject(res.Body)
}

func (vz DeprecationGuide) markdownToObject(markdownReader io.Reader) ([]*collector.OutdatedAPI, error) {
	k8sObjects := make([]*collector.OutdatedAPI, 0)
	scanner := bufio.NewScanner(markdownReader)
	scanner.Split(bufio.ScanLines)
	var currentVersion string
	k8sAPIs := make(map[string][]string)
	for scanner.Scan() {
		line := scanner.Text()
		lineWithoutSpace := strings.TrimSpace(line)
		if len(lineWithoutSpace) == 0 {
			continue
		}
		if strings.Contains(line, "### v1.") {
			currentVersion = strings.Replace(lineWithoutSpace, "###", "", -1)
			if _, ok := k8sAPIs[currentVersion]; !ok {
				k8sAPIs[currentVersion] = []string{}
			}
			continue
		}
		if _, ok := k8sAPIs[currentVersion]; ok {
			if strings.Contains(line, willNoLongerBeServed) || strings.Contains(line, isNoLongerServedAsOf) {
				removedVersion := findVersion(line, []string{willNoLongerBeServed, isNoLongerServedAsOf})
				if len(removedVersion) == 0 {
					continue
				}
				k8sObjects = vz.createAPIObject(line, k8sObjects, removedVersion)
				k8sAPIs[removedVersion] = append(k8sAPIs[removedVersion], line)
			}
		}
	}
	return k8sObjects, nil
}

func (vz DeprecationGuide) createAPIObject(line string, k8sObjects []*collector.OutdatedAPI, removedVersion string) []*collector.OutdatedAPI {
	groups := findResourcesGroups([]string{theUpper}, []string{apiVersionOf, apiVersionsOf, apiVersions}, line, []string{"**"})
	var resources []string
	if strings.HasPrefix(line, theLower) || strings.HasPrefix(line, theUpper) {
		resources = findResourcesGroups([]string{apiVersionOf, apiVersionsOf}, []string{willNoLongerBeServed, isNoLongerServedAsOf}, line, []string{",", and, theLower})
	} else {
		resources = findResourcesGroups([]string{}, []string{in}, line, []string{",", and, theLower})
	}
	for _, api := range groups {
		apiParts := strings.Split(api, "/")
		if len(apiParts) == 2 {
			for _, res := range resources {
				k8sObjects = append(k8sObjects, &collector.OutdatedAPI{Description: line, Removed: removedVersion, Gav: collector.Gvk{Group: apiParts[0], Version: apiParts[1], Kind: res}})
			}
		}
	}
	return k8sObjects
}

func findVersion(line string, keyWords []string) string {
	var partLine string
	for _, keyWord := range keyWords {
		partLine = collector.FindRemovedDeprecatedVersion(strings.ToLower(line), keyWord)
		if strings.HasPrefix(partLine, "v1.") {
			return partLine
		}
	}
	return ""
}

func findResourcesGroups(beginWords []string, endWords []string, line string, removedSigns []string) []string {
	resources := make([]string, 0)
	var beginWord string
	var beginIndex = -1
	var endIndex int
	for _, b := range beginWords {
		beginIndex = strings.Index(line, b)
		if beginIndex == -1 {
			continue
		} else {
			beginWord = b
			break
		}
	}
	for _, e := range endWords {
		endIndex = strings.Index(line, e)
		if endIndex == -1 {
			continue
		} else {
			break
		}
	}
	if beginIndex == -1 {
		beginIndex = 0
	}
	resourceLine := line[beginIndex+len(beginWord) : endIndex]
	splitResource := strings.Split(resourceLine, " ")
	for _, r := range splitResource {
		if len(strings.TrimSpace(r)) == 0 {
			continue
		}
		for _, sign := range removedSigns {
			r = strings.Replace(r, sign, " ", -1)
		}
		r = strings.TrimSpace(r)
		if len(r) == 0 {
			continue
		}
		resources = append(resources, strings.TrimSpace(r))
	}
	return resources
}
