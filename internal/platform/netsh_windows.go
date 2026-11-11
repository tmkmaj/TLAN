//go:build windows

package platform

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// routeLine matches one data row of "netsh interface ipv4 show route":
//
//	No       Manual    7    203.0.113.0/24              1  Loopback Pseudo-Interface 1
//
// The interface column may itself contain spaces, so it is captured greedily.
var routeLine = regexp.MustCompile(`^\s*(?:Yes|No)\s+\S+\s+\S+\s+(\S+)\s+\d+\s+(.+?)\s*$`)

// ensureIPv4Route makes the named interface own a route for prefix with the
// given metric. The route can already exist when Windows created its own entry
// for a newly assigned address, in which case netsh refuses the duplicate and
// the existing entry has to be updated instead.
func ensureIPv4Route(runner Runner, name, prefix string, metric int) error {
	metricValue := strconv.Itoa(metric)
	add := []string{"interface", "ipv4", "add", "route", "prefix=" + prefix, "interface=" + name, "metric=" + metricValue, "store=active"}
	if err := commandWindowsWithRunner(runner, "netsh.exe", add...); err == nil {
		return nil
	}
	update := []string{"interface", "ipv4", "set", "route", "prefix=" + prefix, "interface=" + name, "metric=" + metricValue, "store=active"}
	if err := commandWindowsWithRunner(runner, "netsh.exe", update...); err != nil {
		return fmt.Errorf("route %s on %q: %w", prefix, name, err)
	}
	return nil
}

// routePresent reports whether the named interface owns a route for prefix.
// netsh has no filtered "show route", so the whole active table is inspected.
func routePresent(runner Runner, name, prefix string) (bool, error) {
	output, err := commandOutputWithRunner(runner, "netsh.exe", "interface", "ipv4", "show", "route", "store=active")
	if err != nil {
		return false, fmt.Errorf("query route %q: %w", prefix, err)
	}
	for _, line := range strings.Split(string(output), "\n") {
		match := routeLine.FindStringSubmatch(strings.TrimRight(line, "\r"))
		if match == nil {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(match[1]), prefix) && strings.EqualFold(strings.TrimSpace(match[2]), name) {
			return true, nil
		}
	}
	return false, nil
}

func deleteIPv4Route(runner Runner, name, prefix string) error {
	if err := commandWindowsWithRunner(runner, "netsh.exe", "interface", "ipv4", "delete", "route", "prefix="+prefix, "interface="+name, "store=active"); err != nil {
		return fmt.Errorf("remove route %q: %w", prefix, err)
	}
	return nil
}
