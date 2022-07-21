package outdated

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestMapResources(t *testing.T) {
	tests := []struct {
		name       string
		mdAPI      []*OutdatedAPI
		swaggerAPI map[string]*OutdatedAPI
		want       []K8sAPI
	}{
		{name: "override removed version",
			mdAPI:      []*OutdatedAPI{{Removed: "1.25", Gav: Gvk{Group: "storage.k8s.io", Version: "v1beta1", Kind: "CSIStorageCapacity"}}},
			swaggerAPI: map[string]*OutdatedAPI{"io.k8s.api.storage.k8s.io.v1beta1.CSIStorageCapacity": {Removed: "1.23", Deprecated: "1.21", Gav: Gvk{Group: "storage.k8s.io", Version: "v1beta1", Kind: "CSIStorageCapacity"}}},
			want:       []K8sAPI{{DeprecatedVersion: "1.21", RemovedVersion: "1.25", Version: "v1beta1", Group: "storage.k8s.io", Kind: "CSIStorageCapacity"}},
		},
		{name: "append api",
			mdAPI:      []*OutdatedAPI{{Removed: "1.25", Gav: Gvk{Group: "flowcontrol.apiserver.k8s.io", Version: "v1beta1", Kind: "FlowSchema"}}},
			swaggerAPI: map[string]*OutdatedAPI{"io.k8s.api.storage.k8s.io.v1beta1.CSIStorageCapacity": {Removed: "1.23", Deprecated: "1.21", Gav: Gvk{Group: "storage.k8s.io", Version: "v1beta1", Kind: "CSIStorageCapacity"}}},
			want: []K8sAPI{{DeprecatedVersion: "", RemovedVersion: "1.25", Version: "v1beta1", Group: "flowcontrol.apiserver.k8s.io", Kind: "FlowSchema"},
				{DeprecatedVersion: "1.21", RemovedVersion: "1.23", Version: "v1beta1", Group: "storage.k8s.io", Kind: "CSIStorageCapacity"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MergeMdSwaggerVersions(tt.mdAPI, tt.swaggerAPI)
			for index, r := range got {
				assert.Equal(t, r.Group, tt.want[index].Group)
				assert.Equal(t, r.Version, tt.want[index].Version)
				assert.Equal(t, r.Kind, tt.want[index].Kind)
				assert.Equal(t, r.DeprecatedVersion, tt.want[index].DeprecatedVersion)
				assert.Equal(t, r.RemovedVersion, tt.want[index].RemovedVersion)
			}
		})
	}
}
