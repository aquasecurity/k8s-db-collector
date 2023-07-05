package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_VersionParts(t *testing.T) {

}

func TestStringConfigTable(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    []string
	}{
		{name: "one name one version", version: "aaa-bbb v1.2.3", want: []string{"aaa-bbb", "1.2.3"}},
		{name: "lover one name one version", version: "- secrets-store-csi-driver < v1.3.3", want: []string{"secrets-store-csi-driver", "1.3.3"}},
		{name: "one name two versions and additional", version: "aaa v1.16.0 - v1.18.18 (Note: EndpointSlices were not enabled by default in", want: []string{"aaa", "1.16.0", "1.18.18"}},
		{name: "one name two versions", version: "aaa v1.2.3 - v3.4.5", want: []string{"aaa", "1.2.3", "3.4.5"}},
		{name: "two version", version: "v1.2.3 - v3.4.5", want: []string{"1.2.3", "3.4.5"}},
		{name: "one version", version: "- v3.4.5", want: []string{"3.4.5"}},
		{name: "just header", version: "#### dsdsdsd ", want: []string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := VersionParts(tt.version)
			assert.Equal(t, got, tt.want, tt.name)
		})
	}
}

func TestUpdateLine(t *testing.T) {
	tests := []struct {
		name         string
		versionParts []string
		wantSign     string
		want         string
	}{
		{name: "one name one version", versionParts: []string{"aaa", "1.2.3"}, wantSign: "", want: "- aaa  v1.2.3"},
		{name: "one name one version different sign", versionParts: []string{"aaa", "1.2.3"}, wantSign: "<=", want: "- aaa <= v1.2.3"},
		{name: "one name two versions", versionParts: []string{"aaa", "1.2.3", "3.4.5"}, wantSign: "-", want: "- aaa v1.2.3 - v3.4.5"},
		{name: "two version", versionParts: []string{"1.2.3", "3.4.5"}, wantSign: "-", want: "- v1.2.3 - v3.4.5"},
		{name: "one version", versionParts: []string{"3.4.5"}, want: "-  v3.4.5"},
		{name: "one version other sign", versionParts: []string{"3.4.5"}, wantSign: "<", want: "- < v3.4.5"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := UpdatedLine(tt.versionParts, tt.wantSign)
			assert.Equal(t, got, tt.want, tt.name)
		})
	}
}
