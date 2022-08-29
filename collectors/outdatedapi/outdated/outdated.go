package outdated

import (
	"fmt"
)

//ValidateOutdatedAPI validate outdated data is complete
func ValidateOutdatedAPI(K8sapis map[string]map[string]map[string]string) (map[string]map[string]map[string]string, error) {
	for _, ka := range K8sapis {
		if len(ka) == 0 {
			return nil, fmt.Errorf("failed to get outdated API missing Version or Kind or Group")
		}
		for _, pa := range ka {
			if len(pa) == 0 {
				return nil, fmt.Errorf("failed to get outdated API missing Version or Kind or Group")
			}
		}
	}
	return K8sapis, nil
}
