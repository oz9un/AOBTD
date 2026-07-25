package agent

import "testing"

func TestCleanIDORProbeValuesRejectsSentinelIdentifiers(t *testing.T) {
	got := cleanIDORProbeValues([]string{"NaN", " 7 ", "undefined", "[object Object]", "7", "8"})
	want := []string{"7", "8"}
	if len(got) != len(want) {
		t.Fatalf("values = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("values = %v, want %v", got, want)
		}
	}
}

func TestContainsInvalidPathIdentifier(t *testing.T) {
	for _, raw := range []string{
		"https://example.test/rest/basket/NaN",
		"/api/users/undefined/orders",
		"/api/[object%20Object]",
	} {
		if !containsInvalidPathIdentifier(raw) {
			t.Fatalf("containsInvalidPathIdentifier(%q) = false, want true", raw)
		}
	}
	if containsInvalidPathIdentifier("https://example.test/rest/basket/7") {
		t.Fatal("numeric resource id was treated as invalid")
	}
}
