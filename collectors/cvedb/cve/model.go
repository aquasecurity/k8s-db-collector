package cve

var (
	upstreamOrgName = map[string]string{
		"k8s.io":      "controller-manager,kubelet,apiserver,kubectl,kubernetes,scheduler,proxy",
		"sigs.k8s.io": "secrets-store-csi-driver",
	}

	upstreamRepoName = map[string]string{
		"controller-manager":       "kube-controller-manager",
		"kubelet":                  "kubelet",
		"apiserver":                "apiserver",
		"kubectl":                  "kubectl",
		"kubernetes":               "kubernetes",
		"scheduler":                "kube-scheduler",
		"proxy":                    "kube-proxy",
		"api server":               "apiserver",
		"secrets-store-csi-driver": "secrets-store-csi-driver",
	}
)

type Vulnerability struct {
	ID               string      `json:"id,omitempty"`
	CreatedAt        string      `json:"created_at,omitempty"`
	Summary          string      `json:"summary,omitempty"`
	Component        string      `json:"component,omitempty"`
	Description      string      `json:"details,omitempty"`
	AffectedVersions []*Version  `json:"-"`
	Affected         []*Affected `json:"affected,omitempty"`
	FixedVersions    []*Version  `json:"-"`
	Urls             []string    `json:"references,omitempty"`
	CvssV3           Cvssv3      `json:"cvssv3,omitempty"`
	Severity         string      `json:"severity,omitempty"`
	Major            bool        `json:"-"`
}

type K8sVulnDB struct {
	Cves []*Vulnerability
}

type Cvssv3 struct {
	Vector string
	Score  float64
}

type Version struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
	FixedIndex   int    `json:"-"`
}

type Affected struct {
	Ranges []*Range `json:"ranges,omitempty"`
}

type Range struct {
	Events    []*Event `json:"events,omitempty"`
	RangeType string   `json:"type,omitempty"`
}

type Event struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}
