package main

import (
	"fmt"
	"go-inject/inject"
	"os"
)

func main() {
	payload := os.Args[1]
	uuids := inject.ConvertToUUIDS(payload)
	for _, uuid := range uuids {
		fmt.Printf("\"%s\",\n", uuid)
	}
}
