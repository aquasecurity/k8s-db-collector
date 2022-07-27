package lifecycle

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"io/ioutil"
	"k8s-outdated/collectors/outdatedapi/outdated"
	"net/http"
	"strings"
)

const (
	k8sMasterReleaseTarBall = "https://codeload.github.com/kubernetes/kubernetes/legacy.tar.gz/refs/heads/master"
	preReleaseLifeCycleFile = "zz_generated.prerelease-lifecycle.go"
	k8sapiSeperator         = "k8s.io/api/"

	// lifecycle implementing methods
	apiLifecycleIntroduce   = "APILifecycleIntroduced"
	apiLifecycleDeprecated  = " APILifecycleDeprecated"
	apiLifecycleReplacement = "APILifecycleReplacement"
	apiLifecycleRemoved     = "APILifecycleRemoved"
)

//PreRelease object
type PreRelease struct{}

//NewPreRelease instansiate new DeprecationGuide
func NewPreRelease() *PreRelease {
	return &PreRelease{}
}

//CollectLifCycleAPI colllect api info deprecation / removal and replacment info as implemented by designated APIs
func CollectLifCycleAPI() (*outdated.K8sAPI, error) {
	resp, err := http.Get(k8sMasterReleaseTarBall)
	if err != nil {
		return nil, err
	}
	defer func() {
		err := resp.Body.Close()
		if err != nil {
			fmt.Println(err.Error())
		}
	}()

return nil,err
}

func (pr PreRelease) parsePreReleaseLifecycle(gv string, r io.Reader) map[string]*outdated.K8sAPI {
	apisMap := make(map[string]*outdated.K8sAPI)
	scanner := bufio.NewScanner(r)
	scanner.Split(bufio.ScanLines)
	groupVersion := strings.Split(gv, "/")
	if len(groupVersion) != 2 {
		return nil
	}
	var group, version, kind string
	group = groupVersion[0]
	version = groupVersion[1]
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, apiLifecycleIntroduce) {
			kind = findResource(line, []string{apiLifecycleIntroduce, "()", "{", "}", "func", "in", "", "major", "minor", "int", "*"})
			if _, ok := apisMap[fmt.Sprintf("%s/%s", gv, kind)]; !ok {
				apisMap[fmt.Sprintf("%s/%s", gv, kind)] = &outdated.K8sAPI{Group: group, Version: version, Kind: kind}
			}
			if scanner.Scan() {
				version := findVersion(scanner.Text(), []string{"return"})
				apisMap[fmt.Sprintf("%s/%s", gv, kind)].IntroducedVersion = version
			}
			continue
		}
		if strings.Contains(line, apiLifecycleDeprecated) {
			kind = findResource(line, []string{apiLifecycleDeprecated, "()", "{", "}", "func", "in", "major", "minor", "int", "*"})
			if _, ok := apisMap[fmt.Sprintf("%s/%s", gv, kind)]; !ok {
				apisMap[fmt.Sprintf("%s/%s", gv, kind)] = &outdated.K8sAPI{Group: group, Version: version, Kind: kind}
			}
			if scanner.Scan() {
				version := findVersion(scanner.Text(), []string{"return"})
				apisMap[fmt.Sprintf("%s/%s", gv, kind)].DeprecatedVersion = version
			}
			continue
		}
		if strings.Contains(line, apiLifecycleReplacement) {
			kind = findResource(line, []string{apiLifecycleReplacement, "()", "{", "}", "func", "in", "schema.GroupVersionKind", "*"})
			if _, ok := apisMap[fmt.Sprintf("%s/%s", gv, kind)]; !ok {
				apisMap[fmt.Sprintf("%s/%s", gv, kind)] = &outdated.K8sAPI{Group: group, Version: version, Kind: kind}
			}
			if scanner.Scan() {
				version := findReplacmentAPI(scanner.Text(), []string{"return", "Group", ":", "Version", "Kind"})
				apisMap[fmt.Sprintf("%s/%s", gv, kind)].DeprecatedVersion = version
			}
			continue
		}
		if strings.Contains(line, apiLifecycleRemoved) {
			kind = findResource(line, []string{apiLifecycleRemoved, "()", "{", "}", "func", "in", "schema.GroupVersionKind", "*"})
			if _, ok := apisMap[fmt.Sprintf("%s/%s", gv, kind)]; !ok {
				apisMap[fmt.Sprintf("%s/%s", gv, kind)] = &outdated.K8sAPI{Group: group, Version: version, Kind: kind}
			}
			if scanner.Scan() {
				version := findVersion(scanner.Text(), []string{"return"})
				apisMap[fmt.Sprintf("%s/%s", gv, kind)].DeprecatedVersion = version
			}
			continue
		}
	}
	return nil
}

func findResource(line string, replacmentKeys []string) string {
	for _, k := range replacmentKeys {
		line = strings.ReplaceAll(line, k, "")
	}
	return strings.TrimSpace(line)
}

func findVersion(line string, replacmentKeys []string) string {
	for _, k := range replacmentKeys {
		line = strings.ReplaceAll(line, k, "")
	}
	verParts := strings.Split(line, ",")
	if len(verParts) == 2 {
		return fmt.Sprintf("v%s.%s", verParts[0], verParts[1])
	}
	return ""
}

func findReplacmentAPI(line string, replacmentKeys []string) string {
	for _, l := range replacmentKeys {
		line = strings.ReplaceAll(line, "", l)
	}
	apiParts := strings.Split(line, ",")
	if len(apiParts) == 3 {
		return fmt.Sprintf("%s.%s.%s", apiParts[0], apiParts[1], apiParts[2])
	}
	return ""
}

// Untar API lifecycle implemenation object data from k8s repository
func Untar(reader io.ReadCloser) (map[string]string, error) {
	lifeCycleMap := make(map[string]string)
	gz, err := gzip.NewReader(reader)
	if err != nil {
		return nil, err
	}
	tarReader := tar.NewReader(gz)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}

		info := header.FileInfo()
		if info.Name() == preReleaseLifeCycleFile {
			uname := strings.ReplaceAll(header.Name, fmt.Sprintf("/%s", preReleaseLifeCycleFile), "")
			sname := strings.Split(uname, k8sapiSeperator)
			c, err := ioutil.ReadAll(tarReader)
			if err != nil {
				return nil, err
			}
			if len(sname) < 2 {
				continue
			}
			lifeCycleMap[sname[1]] = string(c)
		}
		continue
	}
	return lifeCycleMap, nil
}
