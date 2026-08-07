package externalrecon

import "testing"

func TestMajorVersion(t *testing.T) {
	for input, want := range map[string]string{"1.0": "1", "2": "2", " 1.4 ": "1"} {
		if got := majorVersion(input); got != want {
			t.Fatalf("majorVersion(%q)=%q", input, got)
		}
	}
}
