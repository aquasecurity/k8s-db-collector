package outdated

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMergeResources(t *testing.T) {
	tests := []struct {
		name       string
		mdAPI      []*OutdatedAPI
		swaggerAPI map[string]*OutdatedAPI
		want       []K8sAPI
	}{
		{name: "override removed version",
			mdAPI:      []*OutdatedAPI{{Removed: "v1.25", Gav: Gvk{Group: "storage.k8s.io", Version: "v1beta1", Kind: "CSIStorageCapacity"}}},
			swaggerAPI: map[string]*OutdatedAPI{"io.k8s.api.storage.k8s.io.v1beta1.CSIStorageCapacity": {Removed: "v1.23", Deprecated: "v1.21", Gav: Gvk{Group: "storage.k8s.io", Version: "v1beta1", Kind: "CSIStorageCapacity"}}},
			want:       []K8sAPI{{DeprecatedVersion: "v1.21", RemovedVersion: "v1.25", Version: "v1beta1", Group: "storage.k8s.io", Kind: "CSIStorageCapacity"}},
		},
		{name: "append api",
			mdAPI: []*OutdatedAPI{{Removed: "v1.25", Gav: Gvk{Group: "flowcontrol.apiserver.k8s.io", Version: "v1beta1", Kind: "FlowSchema"}}},
			swaggerAPI: map[string]*OutdatedAPI{"io.k8s.api.storage.k8s.io.v1beta1.CSIStorageCapacity": {Removed: "v1.23", Deprecated: "v1.21",
				Gav: Gvk{Group: "storage.k8s.io", Version: "v1beta1", Kind: "CSIStorageCapacity"}}},
			want: []K8sAPI{{DeprecatedVersion: "", RemovedVersion: "v1.25", Version: "v1beta1", Group: "flowcontrol.apiserver.k8s.io", Kind: "FlowSchema"},
				{DeprecatedVersion: "v1.21", RemovedVersion: "v1.23", Version: "v1beta1", Group: "storage.k8s.io", Kind: "CSIStorageCapacity"}},
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

func TestValidateOutData(t *testing.T) {
	tests := []struct {
		name     string
		outdated []K8sAPI
		want     *K8sAPI
		hasAPIS  bool
	}{
		{name: "bad removed version", hasAPIS: true,
			outdated: []K8sAPI{{Description: "des", DeprecatedVersion: "v1.21", RemovedVersion: "1.25", Version: "v1beta1", Group: "storage.k8s.io", Kind: "CSIStorageCapacity"}},
			want:     &K8sAPI{Description: "des", DeprecatedVersion: "v1.21", RemovedVersion: "v1.25", Version: "v1beta1", Group: "storage.k8s.io", Kind: "CSIStorageCapacity"},
		},
		{name: "bad deprecated version", hasAPIS: true,
			outdated: []K8sAPI{{Description: "des", DeprecatedVersion: "1.21", RemovedVersion: "v1.25", Version: "v1beta1", Group: "storage.k8s.io", Kind: "CSIStorageCapacity"}},
			want:     &K8sAPI{Description: "des", DeprecatedVersion: "v1.21", RemovedVersion: "v1.25", Version: "v1beta1", Group: "storage.k8s.io", Kind: "CSIStorageCapacity"},
		},
		{name: "bad deprecated version", hasAPIS: true,
			outdated: []K8sAPI{{Description: "des", DeprecatedVersion: "a.a.a", RemovedVersion: "v1.25", Version: "v1beta1", Group: "storage.k8s.io", Kind: "CSIStorageCapacity"}},
			want:     &K8sAPI{Description: "des", DeprecatedVersion: "", RemovedVersion: "v1.25", Version: "v1beta1", Group: "storage.k8s.io", Kind: "CSIStorageCapacity"},
		},
		{name: "no desription", hasAPIS: false,
			outdated: []K8sAPI{{DeprecatedVersion: "v1.21", RemovedVersion: "v1.25", Version: "v1beta1", Group: "storage.k8s.io", Kind: "CSIStorageCapacity"}},
		},
		{name: "no kind", hasAPIS: false,
			outdated: []K8sAPI{{Description: "des", DeprecatedVersion: "v1.21", RemovedVersion: "v1.25", Version: "v1beta1", Group: "storage.k8s.io"}},
		},
		{name: "no group", hasAPIS: false,
			outdated: []K8sAPI{{Description: "des", DeprecatedVersion: "v1.21", RemovedVersion: "v1.25", Version: "v1beta1", Kind: "CSIStorageCapacity"}},
		},
		{name: "no version", hasAPIS: false,
			outdated: []K8sAPI{{Description: "des", DeprecatedVersion: "v1.21", RemovedVersion: "v1.25", Group: "storage.k8s.io", Kind: "CSIStorageCapacity"}},
		},
		{name: "good api", hasAPIS: true,
			outdated: []K8sAPI{{Description: "des", DeprecatedVersion: "v1.21", RemovedVersion: "v1.25", Version: "v1beta1", Group: "storage.k8s.io", Kind: "CSIStorageCapacity"}},
			want:     &K8sAPI{Description: "des", DeprecatedVersion: "v1.21", RemovedVersion: "v1.25", Version: "v1beta1", Group: "storage.k8s.io", Kind: "CSIStorageCapacity"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ValidateOutdatedAPI(tt.outdated)
			if !tt.hasAPIS {
				assert.True(t, len(got) == 0)
			} else {
				assert.Equal(t, tt.want.Kind, got[0].Kind)
				assert.Equal(t, tt.want.Description, got[0].Description)
				assert.Equal(t, tt.want.RemovedVersion, got[0].RemovedVersion)
				assert.Equal(t, tt.want.DeprecatedVersion, got[0].DeprecatedVersion)
				assert.Equal(t, tt.want.Group, got[0].Group)
				assert.Equal(t, tt.want.Version, got[0].Version)
			}
		})
	}
}
