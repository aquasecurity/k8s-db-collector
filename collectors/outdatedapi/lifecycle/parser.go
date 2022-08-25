package lifecycle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"path/filepath"
	"strings"
)

const (
	k8sMasterReleaseTarBall = "https://codeload.github.com/kubernetes/kubernetes/legacy.tar.gz/refs/heads/master"
	preReleaseLifeCycleFile = "zz_generated.prerelease-lifecycle.go"
	k8sapiSeperator         = "k8s.io/api/"
	docsBaseUrl             = "https://github.com/kubernetes/kubernetes/tree/master/staging/src/k8s.io/api"

	// lifecycle implementing methods
	apiLifecycleDeprecated  = "APILifecycleDeprecated"
	apiLifecycleReplacement = "APILifecycleReplacement"
	apiLifecycleRemoved     = "APILifecycleRemoved"
)

//CollectLifCycleAPI collect api info deprecation / removal and replacement info as implemented by designated APIs
func CollectLifCycleAPI() (map[string]map[string]map[string]string, error) {
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
	m, err := Untar(resp.Body)
	if err != nil {
		return nil, err
	}
	gvmOutdatedAPI := make(map[string]map[string]map[string]string)
	for gv, source := range m {
		group, version, err := getGroupVersion(gv)
		if err != nil {
			return nil, err
		}
		asd, err := NewAstReader().Analyze(source)
		if err != nil {
			return nil, err
		}
		for _, d := range asd {
			if len(d.group) != 0 {
				group = d.group
			} else {
				group = fmt.Sprintf("%s.k8s.io", group) //default group suffix
			}
			gv := filepath.Join(group, version)
			_, ok := gvmOutdatedAPI[gv]
			if !ok {
				gvmOutdatedAPI[gv] = make(map[string]map[string]string)
			}
			if _, ok := gvmOutdatedAPI[gv][d.recv]; !ok {
				gvmOutdatedAPI[gv][d.recv] = make(map[string]string)
			}
			switch d.methodName {
			case apiLifecycleDeprecated:
				gvmOutdatedAPI[gv][d.recv]["deprecation_version"] = getVersion(d.returnParams, false)
			case apiLifecycleRemoved:
				gvmOutdatedAPI[gv][d.recv]["removed_version"] = getVersion(d.returnParams, false)
			case apiLifecycleReplacement:
				gvmOutdatedAPI[gv][d.recv]["replacement_version"] = getVersion(d.returnParams, true)

			}
			gvmOutdatedAPI[gv][d.recv]["ref"] = fmt.Sprintf("%s/%s/%s", docsBaseUrl, gv, preReleaseLifeCycleFile)
		}
	}
	return gvmOutdatedAPI, err
}

func getGroupVersion(key string) (string, string, error) {
	gv := strings.Split(key, "/")
	if len(gv) != 2 {
		return "", "", fmt.Errorf("failed to find group version for key: %s", key)
	}
	return gv[0], gv[1], nil
}

func getVersion(nums []string, replacement bool) string {
	var buffer bytes.Buffer

	if !replacement {
		buffer.WriteString("v")
	}
	for _, n := range nums {
		buffer.WriteString(fmt.Sprintf("%s.", strings.Trim(n, `"`)))
	}
	return strings.TrimSuffix(buffer.String(), ".")
}

// Untar API lifecycle implementation object data from k8s repository
func Untar(reader io.ReadCloser) (map[string]string, error) {
	lifeCycleMap := make(map[string]string)
	gz, err := gzip.NewReader(reader)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = gz.Close()
	}()
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
