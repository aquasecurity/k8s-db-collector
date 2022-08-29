package lifecycle

import (
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAnalyze(t *testing.T) {
	tests := []struct {
		name     string
		dataPath string
		want     []AstData
		hasErr   bool
	}{
		{name: "ast parse lifecycle source code", dataPath: "./testdata/fixture/lifecycle_api_source.txt", hasErr: false, want: []AstData{
			{group: "", recv: "AdmissionReview", methodName: "APILifecycleIntroduced", returnParams: []string{"1", "9"}},
			{group: "", recv: "AdmissionReview", methodName: "APILifecycleDeprecated", returnParams: []string{"1", "19"}},
			{group: "\"admission.k8s.io\"", recv: "AdmissionReview", methodName: "APILifecycleReplacement", returnParams: []string{"\"admission.k8s.io\"", "\"v1\"", "\"AdmissionReview\""}},
			{group: "", recv: "AdmissionReview", methodName: "APILifecycleRemoved", returnParams: []string{"1", "22"}}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, err := ioutil.ReadFile(tt.dataPath)
			assert.NoError(t, err)
			assert.NoError(t, err)
			got, err := NewAstReader().Analyze(string(code))
			if tt.hasErr {
				assert.Error(t, err)
			}
			assert.Equal(t, got, tt.want)
		})
	}
}
