//go:build !windows

package main

import "fmt"

func main() {
	fmt.Println("TLAN is a Windows GUI build; use tlan-server on Linux")
}
