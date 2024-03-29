package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/aquasecurity/k8s-db-collector/collectors/cvedb"
	c "github.com/aquasecurity/k8s-db-collector/collectors/cvedb/utils"
	"github.com/aquasecurity/k8s-db-collector/collectors/outdatedapi"
	u "github.com/aquasecurity/k8s-db-collector/collectors/outdatedapi/utils"
	"github.com/aquasecurity/vuln-list-update/git"
	"github.com/aquasecurity/vuln-list-update/utils"
	"golang.org/x/xerrors"
)

const (
	repoURL          = "https://%s@github.com/%s/%s.git"
	defaultRepoOwner = "aquasecurity"
)

var (
	target     = flag.String("target", "", "update target db (k8s-api,k8s-vulndb)")
	githubRepo = flag.String("repo", "trivy-db-data", "github repo db (trivy-db-data,vuln-list-k8s)")
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	flag.Parse()
	now := time.Now().UTC()
	gc := &git.Config{}
	debug := os.Getenv("VULN_LIST_DEBUG") != ""

	repoOwner := utils.LookupEnv("REPOSITORY_OWNER", defaultRepoOwner)
	repoName := utils.LookupEnv("REPOSITORY_NAME", *githubRepo)
	// Embed GitHub token to URL
	githubToken := os.Getenv("GITHUB_TOKEN")
	url := fmt.Sprintf(repoURL, githubToken, repoOwner, repoName)

	log.Printf("target repository is %s/%s\n", repoName, repoName)

	dir := u.K8sAPIDir()
	if repoName == "vuln-list-k8s" {
		dir = c.K8sCveDir()
	}
	if _, err := gc.CloneOrPull(url, dir, "main", debug); err != nil {
		return fmt.Errorf("clone or pull error: %w", err)
	}

	defer func() {
		if debug {
			return
		}
		log.Println("git reset & clean")
		_ = gc.Clean(dir)
	}()

	var commitMsg string
	switch *target {
	case "k8s-api":
		ui := outdatedapi.NewUpdater()
		if err := ui.Update(); err != nil {
			return fmt.Errorf("k8s outdated api update error: %w", err)
		}
		commitMsg = "k8s-outdated-api"
		if err := u.SetLastUpdatedDate(*target, now); err != nil {
			return err
		}
	case "k8s-vulndb":
		u := cvedb.NewUpdater()
		if err := u.Update(); err != nil {
			return fmt.Errorf("k8s vulndb cves update error: %w", err)
		}
		commitMsg = "k8s-vulndb-cves"
		if err := c.SetLastUpdatedDate(*target, now); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown target")
	}

	log.Println("git status")
	files, err := gc.Status(dir)
	if err != nil {
		return fmt.Errorf("git status error: %w", err)
	}

	// only last_updated.json
	if len(files) < 1 {
		log.Println("Skip commit and push")
		return nil
	}

	log.Println("git commit")
	if err = gc.Commit(dir, "./", commitMsg); err != nil {
		return fmt.Errorf("git commit error: %w", err)
	}

	log.Println("git push")
	if err = gc.Push(dir, "main"); err != nil {
		return xerrors.Errorf("git push error: %w", err)
	}

	return nil
}
