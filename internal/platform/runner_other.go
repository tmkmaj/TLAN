//go:build !windows

package platform

import (
	"context"
	"fmt"
	"os/exec"
	"time"
)

type SystemRunner struct{}

func (SystemRunner) Run(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return output, fmt.Errorf("%s %v: %w: %s", name, args, err, output)
	}
	return output, nil
}
