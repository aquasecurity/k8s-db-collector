package cve

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_ParseVulneDB(t *testing.T) {
	b, err := os.ReadFile("./testdata/k8s-db.json")
	assert.NoError(t, err)
	kvd, err := ParseVulnDBData(b)
	assert.NoError(t, err)
	err = ValidateCveData(kvd.Cves)
	assert.NoError(t, err)
	gotVulnDB, err := json.Marshal(kvd.Cves)
	assert.NoError(t, err)
	os.WriteFile("./testdata/expected-vulndb.json", gotVulnDB, 0644)
	wantVulnDB, err := os.ReadFile("./testdata/expected-vulndb.json")
	assert.NoError(t, err)
	fmt.Println(string(wantVulnDB))
	fmt.Println(string(gotVulnDB))
	assert.Equal(t, string(wantVulnDB), string(gotVulnDB))
}
