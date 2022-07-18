package swagger

import (
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"k8s-outdated/collector"
	"testing"
)

func TestMapResources(t *testing.T) {
	tests := []struct {
		name         string
		filePath     string
		markDownLine string
		values       []string
		ExpectedData []*collector.OutdatedAPI
	}{
		{name: "k8s api v1.20.1 apis", filePath: "./testdata/fixture/k8s_v1.20.1.api.json", values: []string{
			"io.k8s.api.rbac.v1alpha1.ClusterRoleBinding", "io.k8s.api.rbac.v1alpha1.RoleBinding"}, ExpectedData: []*collector.OutdatedAPI{
			{Deprecated: "v1.17", Removed: "v1.22", Gav: collector.Gvk{Group: "rbac.authorization.k8s.io", Version: "v1alpha1", Kind: "ClusterRoleBinding"}},
			{Deprecated: "v1.17", Removed: "v1.22", Gav: collector.Gvk{Group: "rbac.authorization.k8s.io", Version: "v1alpha1", Kind: "RoleBinding"}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var versions map[string]interface{}
			byt, err := ioutil.ReadFile(tt.filePath)
			assert.NoError(t, err)
			err = json.Unmarshal(byt, &versions)
			assert.NoError(t, err)
			k8sObjMap, err := NewOpenAPISpec().versionToDetails([]map[string]interface{}{versions})
			assert.NoError(t, err)
			for index, api := range tt.values {
				assert.Equal(t, k8sObjMap[api].Deprecated, tt.ExpectedData[index].Deprecated)
				assert.Equal(t, k8sObjMap[api].Removed, tt.ExpectedData[index].Removed)
				assert.Equal(t, k8sObjMap[api].Gav.Group, tt.ExpectedData[index].Gav.Group)
				assert.Equal(t, k8sObjMap[api].Gav.Kind, tt.ExpectedData[index].Gav.Kind)
				assert.Equal(t, k8sObjMap[api].Gav.Version, tt.ExpectedData[index].Gav.Version)
			}
		})
	}
}
