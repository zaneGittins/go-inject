package main

import (
	"fmt"
	"os"

	"github.com/zaneGittins/go-inject/inject"
)

func main() {
	payload := os.Args[1]
	uuids := inject.ConvertToUUIDS(payload)
	for _, uuid := range uuids {
		fmt.Printf("\"%s\",\n", uuid)
	}
}
