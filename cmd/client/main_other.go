//go:build !windows

package main

import "fmt"

func main() {
	fmt.Println("TmkNetworkLAN is a Windows GUI build; use tmknetworklan-server on Debian/Linux")
}
