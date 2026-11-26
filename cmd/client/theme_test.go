//go:build windows

package main

import "testing"

func TestNormalizeAppearance(t *testing.T) {
	for _, test := range []struct{ input, want string }{{"", "system"}, {"system", "system"}, {"light", "light"}, {"dark", "dark"}, {"unknown", "system"}} {
		if got := normalizeAppearance(test.input); got != test.want {
			t.Fatalf("normalizeAppearance(%q)=%q want %q", test.input, got, test.want)
		}
	}
}

func TestResolveAppearance(t *testing.T) {
	if dark := resolveAppearance("dark", false); !dark {
		t.Fatal("explicit dark was ignored")
	}
	if dark := resolveAppearance("light", true); dark {
		t.Fatal("explicit light was ignored")
	}
	if dark := resolveAppearance("system", true); !dark {
		t.Fatal("system dark was ignored")
	}
	if dark := resolveAppearance("system", false); dark {
		t.Fatal("system light was ignored")
	}
}

func TestAppearanceSelection(t *testing.T) {
	for _, test := range []struct {
		value string
		index int
	}{{"system", 0}, {"light", 1}, {"dark", 2}, {"invalid", 0}} {
		if got := appearanceIndex(test.value); got != test.index {
			t.Fatalf("appearanceIndex(%q)=%d", test.value, got)
		}
		if got := appearanceFromIndex(test.index); got != normalizeAppearance(test.value) {
			t.Fatalf("appearanceFromIndex(%d)=%q", test.index, got)
		}
	}
}

func TestPaletteSlotsAreUnique(t *testing.T) {
	if got := len(paletteReplacements(lightPalette, darkPalette)); got != 24 {
		t.Fatalf("light->dark replacement map has %d entries, want 24 unique slots", got)
	}
	if got := len(paletteReplacements(darkPalette, lightPalette)); got != 24 {
		t.Fatalf("dark->light replacement map has %d entries, want 24 unique slots", got)
	}
}
