package markdown

import (
	"github.com/stretchr/testify/assert"
	"k8s-outdated/collector"
	"strings"
	"testing"
)

func TestMapResources(t *testing.T) {
	tests := []struct {
		name         string
		K8sObject    []collector.OutdatedAPI
		markDownLine string
	}{
		{name: "line #1 ", K8sObject: []collector.OutdatedAPI{{Removed: "v1.27", Gav: collector.Gvk{Version: "v1beta1", Group: "storage.k8s.io", Kind: "CSIStorageCapacity"}}}, markDownLine: "### v1.27\n\nThe **v1.27** release will stop serving theUpper following deprecated API versions:\n\n#### CSIStorageCapacity {#csistoragecapacity-v127}\n\nThe **storage.k8s.io/v1beta1** API version of CSIStorageCapacity will no longer be served in v1.27."},
		{name: "line #2 ", K8sObject: []collector.OutdatedAPI{{Removed: "v1.26", Gav: collector.Gvk{Version: "v1beta1", Group: "flowcontrol.apiserver.k8s.io", Kind: "FlowSchema"}},
			{Removed: "v1.26", Gav: collector.Gvk{Version: "v1beta1", Group: "flowcontrol.apiserver.k8s.io", Kind: "PriorityLevelConfiguration"}}}, markDownLine: "### v1.26\n\nThe **v1.26** release will stop serving theUpper following deprecated API versions:\n\n#### Flow control resources {#flowcontrol-resources-v126}\n\nThe **flowcontrol.apiserver.k8s.io/v1beta1** API version of FlowSchema and PriorityLevelConfiguration will no longer be served in v1.26."},
		{name: "line #3 ", K8sObject: []collector.OutdatedAPI{{Removed: "v1.25", Gav: collector.Gvk{Version: "v1beta1", Group: "batch", Kind: "CronJob"}}}, markDownLine: "### v1.25\n\nThe **v1.25** release will stop serving theUpper following deprecated API versions:\n\n#### CronJob {#cronjob-v125}\n\nThe **batch/v1beta1** API version of CronJob will no longer be served in v1.25."},
		{name: "line #4 ", K8sObject: []collector.OutdatedAPI{{Removed: "v1.25", Gav: collector.Gvk{Version: "v2beta1", Group: "autoscaling", Kind: "HorizontalPodAutoscaler"}}}, markDownLine: "### v1.25\n\n#### HorizontalPodAutoscaler {#horizontalpodautoscaler-v125}\n\nThe **autoscaling/v2beta1** API version of HorizontalPodAutoscaler will no longer be served in v1.25."},
		{name: "line #5 ", K8sObject: []collector.OutdatedAPI{{Removed: "v1.22", Gav: collector.Gvk{Version: "v1beta1", Group: "admissionregistration.k8s.io", Kind: "MutatingWebhookConfiguration"}},
			{Removed: "v1.22", Gav: collector.Gvk{Version: "v1beta1", Group: "admissionregistration.k8s.io", Kind: "ValidatingWebhookConfiguration"}}}, markDownLine: "### v1.22\n\nThe **v1.22** release stopped serving theUpper following deprecated API versions:\n\n#### Webhook resources {#webhook-resources-v122}\n\nThe **admissionregistration.k8s.io/v1beta1** API version of MutatingWebhookConfiguration and ValidatingWebhookConfiguration is no longer served as of v1.22."},
		{name: "line #6 ", K8sObject: []collector.OutdatedAPI{{Removed: "v1.25", Gav: collector.Gvk{Version: "v2beta1", Group: "node.k8s.io", Kind: "RuntimeClass"}}}, markDownLine: "\t\t{name: \"line #4 \", OutdatedAPI: []collector.OutdatedAPI{{Removed: \"v1.25\", Gvk: collector.Gvk{Version: \"v2beta1\", Group: \"autoscaling\", Kind: \"HorizontalPodAutoscaler\"}}}, markDownLine: \"### v1.25\\n\\n#### HorizontalPodAutoscaler {#horizontalpodautoscaler-v125}\\n\\nThe **autoscaling/v2beta1** API version of HorizontalPodAutoscaler will no longer be served in v1.25.\"},\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k8sObj, err := NewDeprecationGuide().markdownToObject(strings.NewReader(tt.markDownLine))
			assert.NoError(t, err)
			for index, obj := range k8sObj {
				assert.Equal(t, obj.Gav.Version, tt.K8sObject[index].Gav.Version)
				assert.Equal(t, obj.Gav.Group, tt.K8sObject[index].Gav.Group)
				assert.Equal(t, obj.Gav.Kind, tt.K8sObject[index].Gav.Kind)
				assert.Equal(t, obj.Removed, tt.K8sObject[index].Removed)
			}
		})
	}
}
