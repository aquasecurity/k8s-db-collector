package main

import (
	"encoding/json"
	"fmt"
	"k8s-outdated/collectors/outdatedapi"
	"k8s-outdated/collectors/outdatedapi/markdown"
	"k8s-outdated/collectors/outdatedapi/swagger"
	"os"
)

func main() {
	if len(os.Args[1:]) == 0 {
		fmt.Println("k8s version param is missing")
		os.Exit(1)
	}
	// parse deprecate and removed versions from k8s swagger api
	mDetails, err := swagger.NewOpenAPISpec().CollectOutdatedAPI(os.Args[1:][0])
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	// parse removed version from k8s deprecation mark down docs
	objs, err := markdown.NewDeprecationGuide().CollectOutdatedAPI()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	// merge swagger and markdown results
	apis := outdatedapi.MergeMdSwaggerVersions(objs, mDetails)
	data, err := json.Marshal(apis)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(string(data))

}
