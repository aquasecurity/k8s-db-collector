package outdated

import (
	"encoding/json"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateOutdatedAPI(t *testing.T) {
	tests := []struct {
		name     string
		dataPath string
		hasErr   bool
	}{
		{name: "complete outdated api data", dataPath: "./testdata/fixture/outdated_api.json", hasErr: false},
		{name: "missing all outdated api data", dataPath: "./testdata/fixture/outdated_api_missing_all.json", hasErr: true},
		{name: "missing partial outdated api data", dataPath: "./testdata/fixture/outdated_api_missing_partial.json", hasErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fdata, err := ioutil.ReadFile(tt.dataPath)
			assert.NoError(t, err)
			var outdatedAPI map[string]map[string]map[string]string
			err = json.Unmarshal(fdata, &outdatedAPI)
			assert.NoError(t, err)
			_, err = ValidateOutdatedAPI(outdatedAPI)
			if tt.hasErr {
				assert.Error(t, err)
			}
		})
	}
}
