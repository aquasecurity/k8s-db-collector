package collector

import (
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

const (
	willNoLongerBeServed = "will no longer be served in"
	isNoLongerServedAsOf = "is no longer served as of"
	removedIn            = "removal in"
	deprecatedIn         = "deprecated in"
)

func TestTextUtil(t *testing.T) {
	tests := []struct {
		name string
		line string
		verb string
		want string
	}{
		{name: "line with willNoLongerBeServed ", want: "v1.22", verb: willNoLongerBeServed, line: "ClusterRole is a cluster level, logical grouping of PolicyRules that can be referenced as a unit by a RoleBinding or ClusterRoleBinding. Deprecated in v1.17 in favor of rbac.authorization.k8s.io/v1 ClusterRole, and will no longer be served in v1.22."},
		{name: "line with isNoLongerServedAsOf ", want: "v1.22", verb: isNoLongerServedAsOf, line: "The **admissionregistration.k8s.io/v1beta1** API version of MutatingWebhookConfiguration and ValidatingWebhookConfiguration is no longer served as of v1.22."},
		{name: "line with removedIn ", want: "v1.19", verb: removedIn, line: "MutatingWebhookConfiguration describes the configuration of and admission webhook that accept or reject and may change the object. Deprecated in v1.16, planned for removal in v1.19. Use admissionregistration.k8s.io/v1 MutatingWebhookConfiguration instead."},
		{name: "line with deprecatedIn ", want: "v1.16", verb: deprecatedIn, line: "MutatingWebhookConfiguration describes the configuration of and admission webhook that accept or reject and may change the object. Deprecated in v1.16, planned for removal in v1.19. Use admissionregistration.k8s.io/v1 MutatingWebhookConfiguration instead."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FindRemovedDeprecatedVersion(strings.ToLower(tt.line), tt.verb)
			assert.Equal(t, got, tt.want)
		})
	}
}
