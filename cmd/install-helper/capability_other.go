//go:build !linux

package main

import "errors"

func setBindCapability(string) error { return errors.New("file capabilities require Linux") }
