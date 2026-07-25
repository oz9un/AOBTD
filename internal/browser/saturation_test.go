package browser

import "testing"

func TestInterestingPathUsesRouteSegmentsNotSubstrings(t *testing.T) {
	for _, raw := range []string{
		"https://app.test/author/Ada-Lovelace/",
		"https://app.test/tag/authors/page/1/",
		"https://app.test/tag/authorization/page/1/",
	} {
		if IsInterestingPath(raw) {
			t.Fatalf("ordinary content route became security-interesting via substring: %s", raw)
		}
	}
	for _, raw := range []string{
		"https://app.test/auth/login",
		"https://app.test/reset-password",
		"https://app.test/api/v1/accounts",
		"https://app.test/#/admin/users",
	} {
		if !IsInterestingPath(raw) {
			t.Fatalf("security-relevant route was not preserved: %s", raw)
		}
	}
}
