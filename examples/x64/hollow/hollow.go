package main

import (
	"flag"
	"fmt"
	"io/ioutil"

	"github.com/zaneGittins/go-inject/inject"
)

func main() {

	source := flag.String("source", "", "Source executable")
	replace := flag.String("replace", "", "Destination executable")
	flag.Parse()

	fmt.Printf("Replacing %s with %s\n", *source, *replace)

	data, _ := ioutil.ReadFile(*replace)
	inject.RunPE64(data, *source, "")
}
