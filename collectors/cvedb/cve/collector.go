package cve

import (
	"io"
	"net/http"
)

const (
	k8svulnDBURL = "https://kubernetes.io/docs/reference/issues-security/official-cve-feed/index.json"
)

func Collect() (*K8sVulnDB, error) {
	response, err := http.Get(k8svulnDBURL)
	if err != nil {
		return nil, err
	}
	bodyBytes, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	vulndbCves, err := ParseVulnDB(bodyBytes)
	if err != nil {
		return nil, err
	}
	err = ValidateCveData(vulndbCves.Cves)
	if err != nil {
		return nil, err
	}
	return vulndbCves, nil
}
