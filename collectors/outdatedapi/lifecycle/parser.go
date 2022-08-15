package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"io/ioutil"
	"k8s-outdated/collectors/outdatedapi/outdated"
	"net/http"
	"path/filepath"
	"strings"
)

const (
	k8sMasterReleaseTarBall = "https://codeload.github.com/kubernetes/kubernetes/legacy.tar.gz/refs/heads/master"
	preReleaseLifeCycleFile = "zz_generated.prerelease-lifecycle.go"
	k8sapiSeperator         = "k8s.io/api/"

	// lifecycle implementing methods

	apiLifecycleDeprecated  = "APILifecycleDeprecated"
	apiLifecycleReplacement = "APILifecycleReplacement"
	apiLifecycleRemoved     = "APILifecycleRemoved"
)

//CollectLifCycleAPI collect api info deprecation / removal and replacement info as implemented by designated APIs
func CollectLifCycleAPI() ([]*outdated.K8sAPI, error) {
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
	astReader := NewAstReader()
	gvmOutdatedAPI := make(map[string]*outdated.K8sAPI)
	outdatedArr := make([]*outdated.K8sAPI, 0)
	for key, val := range m {
		gv := strings.Split(key, "/")
		if len(gv) != 2 {
			continue
		}
		group := gv[0]
		version := gv[1]
		asd, err := astReader.Analyze(val)
		if err != nil {
			return nil, err
		}
		var data *outdated.K8sAPI
		for _, d := range asd {
			gvk := filepath.Join(group, version, d.recv)
			_, ok := gvmOutdatedAPI[gvk]
			if !ok {
				gvmOutdatedAPI[gvk] = &outdated.K8sAPI{Kind: d.recv, Group: group, Version: version}
			}
			data = gvmOutdatedAPI[gvk]
			switch d.methodName {
			case apiLifecycleDeprecated:
				data.DeprecatedVersion = getVersion(d.returnParams, false)
			case apiLifecycleRemoved:
				data.RemovedVersion = getVersion(d.returnParams, false)
			case apiLifecycleReplacement:
				data.ReplacementVersion = getVersion(d.returnParams, true)
			}
		}
		outdatedArr = append(outdatedArr, data)
	}
	return outdatedArr, err
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
