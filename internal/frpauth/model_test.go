package frpauth

import (
	"strings"
	"testing"
)

func TestNormalizeAllowUsersAllowsWildcard(t *testing.T) {
	got, err := normalizeAllowUsers([]string{"peer-b", "*", "peer-a", "peer-a"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != "*,peer-a,peer-b" {
		t.Fatalf("normalized allow users = %#v", got)
	}
}
