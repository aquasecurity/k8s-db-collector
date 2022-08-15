package main

import "fmt"

func main() {
	oda, err := CollectLifCycleAPI()
	if err != nil {
		panic(err)
	}
	fmt.Println(oda)
}
