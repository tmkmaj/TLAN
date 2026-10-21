package main

// updateMaskedValue converts an edit made against a one-rune-per-secret mask
// back into the real token value. The mask and token use the same rune count,
// so insertions, deletions, replacements and pastes retain their positions.
func updateMaskedValue(actual, displayed, edited []rune) (next, inserted []rune, caret int) {
	prefix := 0
	for prefix < len(displayed) && prefix < len(edited) && displayed[prefix] == edited[prefix] {
		prefix++
	}
	suffix := 0
	for suffix < len(displayed)-prefix &&
		suffix < len(edited)-prefix &&
		displayed[len(displayed)-1-suffix] == edited[len(edited)-1-suffix] {
		suffix++
	}
	removed := len(displayed) - prefix - suffix
	inserted = append([]rune(nil), edited[prefix:len(edited)-suffix]...)

	if prefix > len(actual) {
		prefix = len(actual)
	}
	if removed > len(actual)-prefix {
		removed = len(actual) - prefix
	}
	next = make([]rune, 0, len(actual)-removed+len(inserted))
	next = append(next, actual[:prefix]...)
	next = append(next, inserted...)
	next = append(next, actual[prefix+removed:]...)
	caret = prefix + len(inserted)
	return next, inserted, caret
}
