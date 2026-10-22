//go:build windows

package platform

import (
	"strings"
	"testing"
)

func TestCleanPowerShellOutputRemovesCLIXMLProgress(t *testing.T) {
	input := "#< CLIXML\r\n{11111111-1111-1111-1111-111111111111}\r\n<Objs Version=\"1.1.0.1\"><Obj><S S=\"progress\" /></Obj></Objs>\r\n</Objs>\r\n"
	output := string(cleanPowerShellOutput([]byte(input)))
	if output != "{11111111-1111-1111-1111-111111111111}\n" {
		t.Fatalf("cleaned output = %q", output)
	}
	if strings.Contains(output, "CLIXML") || strings.Contains(output, "<Objs") {
		t.Fatal("CLIXML metadata remained in command output")
	}
}
