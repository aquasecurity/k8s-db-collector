package main

import (
	"flag"
	"fmt"
	"github.com/aquasecurity/vuln-list-update/git"
	"github.com/aquasecurity/vuln-list-update/utils"
	"golang.org/x/xerrors"
	"k8s-outdated/collectors/outdatedapi"
	"log"
	"os"
	"time"
)

const (
	repoURL          = "https://%s@github.com/%s/%s.git"
	defaultRepoOwner = "aquasecurity"
	defaultRepoName  = "trivy-db-data"
)

var (
	target = flag.String("target", "k8s-api", "update target (k8s-api)")
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

	repoOwner := utils.LookupEnv("DBDATA_REPOSITORY_OWNER", defaultRepoOwner)
	repoName := utils.LookupEnv("TRIVY_DB_DATA_REPOSITORY_NAME", defaultRepoName)

	// Embed GitHub token to URL
	githubToken := os.Getenv("GITHUB_TOKEN")
	url := fmt.Sprintf(repoURL, githubToken, repoOwner, repoName)

	log.Printf("target repository is %s/%s\n", repoOwner, repoName)

	dir := outdatedapi.K8sAPIDir()
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
		u := outdatedapi.NewUpdater()
		if err := u.Update(); err != nil {
			return fmt.Errorf("k8s outdated api update error: %w", err)
		}
		commitMsg = "k8s-outdated-api"
	default:
		return fmt.Errorf("unknown target")
	}

	if debug {
		return nil
	}

	if err := utils.SetLastUpdatedDate(*target, now); err != nil {
		return err
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
