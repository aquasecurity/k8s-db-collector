package cvedb

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"path/filepath"

	"github.com/aquasecurity/k8s-db-collector/collectors"
	"github.com/aquasecurity/k8s-db-collector/collectors/cvedb/cve"
	"github.com/aquasecurity/k8s-db-collector/collectors/cvedb/utils"
	"golang.org/x/xerrors"

	"os"
)

const (
	version        = "1.0.0"
	k8sAPIFileName = "k8s-cve-list.json"
	cveFolder      = "k8s-cves"
)

// Updater fetch k8s outdated API Object
type Updater struct {
	*options
}

// NewUpdater return new updater instance
func NewUpdater(opts ...option) Updater {
	o := &options{
		k8sdDir:   utils.K8sCveDir(),
		cveFolder: filepath.Join(collectors.MainFolder, cveFolder),
		version:   version,
	}
	for _, opt := range opts {
		opt(o)
	}
	return Updater{
		options: o,
	}
}

type options struct {
	version   string
	k8sdDir   string
	cveFolder string
}

type option func(*options)

func (u Updater) Update() error {
	log.Println("Fetching k8s vulndb cve data...")
	vulnDB, err := cve.Collect()
	if err != nil {
		return err
	}
	if len(vulnDB.Cves) == 0 {
		return fmt.Errorf("no outdated api data to publish")
	}
	data, err := json.Marshal(vulnDB)
	if err != nil {
		return err
	}
	fp := filepath.Join(u.k8sdDir, u.cveFolder)
	log.Printf("Remove k8s vulndb cves directory %s", fp)
	if err := os.RemoveAll(fp); err != nil {
		return fmt.Errorf("failed to remove k8s vulndb cves directory: %w", err)
	}
	if err := os.MkdirAll(fp, 0755); err != nil {
		return fmt.Errorf("mkdir error: %w", err)
	}
	filePath := filepath.Join(fp, k8sAPIFileName)
	var prettyJSON bytes.Buffer
	if err := json.Indent(&prettyJSON, data, "", "\t"); err != nil {
		return fmt.Errorf("failed ro format json: %w", err)
	}
	if err = os.WriteFile(filePath, prettyJSON.Bytes(), 0644); err != nil {
		return xerrors.Errorf("write error: %w", err)
	}

	return nil
}
