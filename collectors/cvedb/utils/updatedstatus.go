package utils

import (
	"encoding/json"

	"os"
	"path/filepath"
	"time"

	"golang.org/x/xerrors"
)

const (
	lastUpdatedFile = "last_updated.json"
)

var (
	lastUpdatedFilePath = filepath.Join(K8sCveDir(), lastUpdatedFile)
)

type LastUpdated map[string]time.Time

func GetLastUpdatedDate(dist string) (time.Time, error) {
	lastUpdated, err := getLastUpdatedDate()
	if err != nil {
		return time.Time{}, err
	}

	t, ok := lastUpdated[dist]
	if !ok {
		return time.Unix(0, 0), nil
	}

	return t, nil
}

func getLastUpdatedDate() (map[string]time.Time, error) {
	lastUpdated := LastUpdated{}
	if _, err := os.Stat(lastUpdatedFilePath); os.IsNotExist(err) {
		return lastUpdated, nil
	}

	f, err := os.Open(lastUpdatedFilePath)
	if err != nil {
		return nil, err
	}

	if err = json.NewDecoder(f).Decode(&lastUpdated); err != nil {
		return nil, err
	}

	return lastUpdated, nil
}

func SetLastUpdatedDate(dist string, lastUpdatedDate time.Time) error {
	lastUpdated, err := getLastUpdatedDate()
	if err != nil {
		return xerrors.Errorf("failed to get last updated date: %w", err)
	}
	lastUpdated[dist] = lastUpdatedDate

	b, err := json.MarshalIndent(lastUpdated, "", "  ")
	if err != nil {
		return err
	}
	if err = os.WriteFile(lastUpdatedFilePath, b, 0600); err != nil {
		return xerrors.Errorf("failed to write last updated date: %w", err)
	}

	return nil
}

func K8sCveDir() string {
	return filepath.Join(CacheDir(), "db-vuln-list")
}

func CacheDir() string {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		cacheDir = os.TempDir()
	}
	dir := filepath.Join(cacheDir, "k8s-db-collector")
	return dir
}
