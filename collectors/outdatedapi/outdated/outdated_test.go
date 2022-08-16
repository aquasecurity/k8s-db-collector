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
		hasErr     bool
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
		outdated []*K8sAPI
		want     *K8sAPI
		hasAPIS  bool
		hasError bool
	}{
		{name: "bad removed version", hasAPIS: true,
			outdated: []*K8sAPI{{Description: "des", DeprecatedVersion: "v1.21", RemovedVersion: "", Version: "v1beta1", Group: "storage.k8s.io", Kind: "CSIStorageCapacity"}},
			want:     &K8sAPI{Description: "des", DeprecatedVersion: "v1.21", RemovedVersion: "v1.25", Version: "v1beta1", Group: "storage.k8s.io", Kind: "CSIStorageCapacity"},
			hasError: true,
		},
		{name: "bad deprecated version", hasAPIS: true,
			outdated: []*K8sAPI{{Description: "des", DeprecatedVersion: "", RemovedVersion: "v1.25", Version: "v1beta1", Group: "storage.k8s.io", Kind: "CSIStorageCapacity"}},
			want:     &K8sAPI{Description: "des", DeprecatedVersion: "v1.21", RemovedVersion: "v1.25", Version: "v1beta1", Group: "storage.k8s.io", Kind: "CSIStorageCapacity"},
			hasError: true,
		},
		{name: "bad replace version", hasAPIS: true,
			outdated: []*K8sAPI{{Description: "des", DeprecatedVersion: "a.a.a", ReplacementVersion: "", Version: "v1beta1", Group: "storage.k8s.io", Kind: "CSIStorageCapacity"}},
			want:     &K8sAPI{Description: "des", DeprecatedVersion: "", RemovedVersion: "v1.25", Version: "v1beta1", Group: "storage.k8s.io", Kind: "CSIStorageCapacity"},
			hasError: true,
		},
		{name: "no kind", hasAPIS: false,
			outdated: []*K8sAPI{{Description: "des", DeprecatedVersion: "v1.21", RemovedVersion: "v1.25", Version: "v1beta1", Group: "storage.k8s.io"}},
			hasError: true,
		},
		{name: "no group", hasAPIS: false,
			outdated: []*K8sAPI{{Description: "des", DeprecatedVersion: "v1.21", RemovedVersion: "v1.25", Version: "v1beta1", Kind: "CSIStorageCapacity"}},
			hasError: true,
		},
		{name: "no version", hasAPIS: false,
			outdated: []*K8sAPI{{Description: "des", DeprecatedVersion: "v1.21", RemovedVersion: "v1.25", Group: "storage.k8s.io", Kind: "CSIStorageCapacity"}},
			hasError: true,
		},
		{name: "good api", hasAPIS: true,
			outdated: []*K8sAPI{{Description: "des", DeprecatedVersion: "v1.21", RemovedVersion: "v1.25", Version: "v1beta1", Group: "storage.k8s.io", Kind: "CSIStorageCapacity"}},
			want:     &K8sAPI{Description: "des", DeprecatedVersion: "v1.21", RemovedVersion: "v1.25", Version: "v1beta1", Group: "storage.k8s.io", Kind: "CSIStorageCapacity"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidateOutdatedAPI(tt.outdated)
			if tt.hasError {
				assert.Error(t, err)
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
