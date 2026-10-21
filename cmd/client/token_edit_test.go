package main

import "testing"

func TestUpdateMaskedValue(t *testing.T) {
	cases := []struct {
		name     string
		actual   string
		shown    string
		edited   string
		want     string
		inserted string
		caret    int
	}{
		{"append", "abc", "abc", "abcd", "abcd", "d", 4},
		{"backspace", "abc", "abc", "ab", "ab", "", 2},
		{"replace all", "abc", "abc", "z", "z", "z", 1},
		{"paste", "ab", "ab", "abXYZ", "abXYZ", "XYZ", 5},
		{"insert middle", "abcd", "abcd", "abXYcd", "abXYcd", "XY", 4},
		{"delete middle", "abcd", "abcd", "ad", "ad", "", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, inserted, caret := updateMaskedValue([]rune(tc.actual), []rune(tc.shown), []rune(tc.edited))
			if string(got) != tc.want || string(inserted) != tc.inserted || caret != tc.caret {
				t.Fatalf("got value=%q inserted=%q caret=%d, want value=%q inserted=%q caret=%d", got, inserted, caret, tc.want, tc.inserted, tc.caret)
			}
		})
	}
}
