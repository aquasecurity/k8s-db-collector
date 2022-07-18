package outdatedapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"golang.org/x/xerrors"
	"k8s-outdated/collectors/outdatedapi/outdated"
	"log"
	"path/filepath"

	"k8s-outdated/collectors/outdatedapi/markdown"
	"k8s-outdated/collectors/outdatedapi/swagger"
	"os"
)

const (
	outdatedAPIDir = "k8s-api"
	version        = "1.19.1"
	k8sAPIFileName = "k8s-outdated-api.json"
)

// Updater fetch k8s outdated API Object
type Updater struct {
	*options
}

// NewUpdater return new updater instance
func NewUpdater(opts ...option) Updater {
	o := &options{
		outdatedDir: K8sAPIDir(),
		version:     version,
	}
	for _, opt := range opts {
		opt(o)
	}
	return Updater{
		options: o,
	}
}

type options struct {
	version     string
	outdatedDir string
}

type option func(*options)

//Update latest outdated API list
func (u Updater) Update() error {
	log.Println("Fetching k8s outdated api data...")
	// parse deprecate and removed versions from k8s swagger api
	mDetails, err := swagger.NewOpenAPISpec().CollectOutdatedAPI(u.version)
	if err != nil {
		return err
	}
	// parse removed version from k8s deprecation mark down docs
	objs, err := markdown.NewDeprecationGuide().CollectOutdatedAPI()
	if err != nil {
		return err
	}
	// merge swagger and markdown results
	apis := outdated.MergeMdSwaggerVersions(objs, mDetails)
	data, err := json.Marshal(apis)
	if err != nil {
		return err
	}
	fp := filepath.Join(u.outdatedDir, outdatedAPIDir)
	log.Printf("Remove k8s outdated api directory %s", fp)
	if err := os.RemoveAll(fp); err != nil {
		return fmt.Errorf("failed to remove k8s outdated api directory: %w", err)
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

func K8sAPIDir() string {
	return filepath.Join(CacheDir(), "db-data")
}

func CacheDir() string {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		cacheDir = os.TempDir()
	}
	dir := filepath.Join(cacheDir, "k8s-db-collector")
	return dir
}