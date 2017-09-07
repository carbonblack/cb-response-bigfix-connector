package main

import (
	"fmt"
	"os"
	"os/exec"
)

func main() {
	if len(os.Args) > 1 {
		// run cmd.exe with ping
		out, _ := exec.Command("cmd.exe /c ping 127.0.0.1").Output()
		fmt.Printf("%s", out)
	} else {
		fmt.Println("Hello world")
	}
}