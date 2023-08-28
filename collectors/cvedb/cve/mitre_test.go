package cve

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSanitizedVersion(t *testing.T) {
	tests := []struct {
		Name    string
		Version *MitreVersion
		Want    *MitreVersion
	}{
		{Name: "validate n/a version ", Version: &MitreVersion{Version: "n/a"}, Want: &MitreVersion{Version: "n/a"}},
		{Name: "validate unspecified version ", Version: &MitreVersion{Version: "unspecified"}, Want: &MitreVersion{Version: "unspecified"}},
		{Name: "validate less equal sign in version", Version: &MitreVersion{Version: "<= 1.3.4"}, Want: &MitreVersion{Version: "<= 1.3.4", LessThanOrEqual: "1.3.4"}},
		{Name: "validate less equal sign and version", Version: &MitreVersion{LessThanOrEqual: "<=", Version: "1.3.4"}, Want: &MitreVersion{Version: "1.3.4", LessThanOrEqual: "1.3.4"}},
		{Name: "validate less sign in version", Version: &MitreVersion{Version: "< 1.3.4"}, Want: &MitreVersion{Version: "< 1.3.4", LessThan: "1.3.4"}},
		{Name: "validate prior to then sign in version", Version: &MitreVersion{Version: "prior to 1.3.4"}, Want: &MitreVersion{Version: "1.3.4", LessThan: "1.3.4"}},
		{Name: "validate prior to with major in version", Version: &MitreVersion{Version: "prior to 1.3"}, Want: &MitreVersion{Version: "1.3.0", LessThan: "1.3.0"}},
		{Name: "validate less  with astrix", Version: &MitreVersion{LessThan: "1.3*"}, Want: &MitreVersion{Version: "1.3"}},
		{Name: "validate less  with x", Version: &MitreVersion{Version: "1.3.x"}, Want: &MitreVersion{Version: "1.3"}},
		{Name: "validate less equal sign in version", Version: &MitreVersion{LessThanOrEqual: "<= 1.3.4"}, Want: &MitreVersion{LessThanOrEqual: "1.3.4"}},
	}
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			got, _ := sanitizedVersion(tt.Version)
			assert.Equal(t, got, tt.Want)

		})
	}
}
