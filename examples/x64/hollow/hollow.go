package main

import (
	"flag"
	"fmt"
	"go-inject/inject"
	"io/ioutil"
)

func main() {

	source := flag.String("source", "", "Source executable")
	replace := flag.String("replace", "", "Destination executable")
	flag.Parse()

	fmt.Printf("Replacing %s with %s\n", *source, *replace)

	data, _ := ioutil.ReadFile(*replace)
	inject.RunPE64(data, *source, "")
}
