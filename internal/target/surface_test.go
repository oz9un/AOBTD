package target

import "testing"

func TestSurfaceFamilyRecognizesCoreApplicationJourneys(t *testing.T) {
	tests := []struct {
		url  string
		hint string
		want string
	}{
		{"https://letterboxd.com/reviews/popular/this/week/", "Popular reviews", "review"},
		{"https://letterboxd.com/films/popular/", "Browse films", "catalog"},
		{"https://letterboxd.com/lists/", "Member lists", "collection"},
		{"https://letterboxd.com/members/", "People", "community"},
		{"https://shop.test/sepetim", "Sepetim", "transaction"},
		{"https://registry.test/packages/widget", "Widget package", "catalog"},
		{"https://letterboxd.test/api-beta/", "API dashboard with login form and search functionality", "developer"},
		{"https://app.test/settings/search/", "Search preferences", "account"},
		{"https://app.test/settings/profile", "Account settings", "account"},
		{"https://app.test/privacy-policy", "Privacy policy", "legal"},
	}
	for _, tt := range tests {
		if got := SurfaceFamily(tt.url, tt.hint); got != tt.want {
			t.Errorf("SurfaceFamily(%q, %q) = %q, want %q", tt.url, tt.hint, got, tt.want)
		}
	}
}

func TestSurfaceFamilyUsesQueryKeysButNotValues(t *testing.T) {
	if got := SurfaceFamily("https://app.test/?search=secret-review-token", ""); got != "search" {
		t.Fatalf("query key family = %q, want search", got)
	}
	if got := SurfaceFamily("https://app.test/?next=reviews", ""); got != "" {
		t.Fatalf("query value influenced semantic family: %q", got)
	}
}

func TestSurfaceValuePrefersBusinessJourneysOverChrome(t *testing.T) {
	if SurfaceValue("review") <= SurfaceValue("account") {
		t.Fatal("review journey should outrank account chrome before novelty")
	}
	if SurfaceValue("catalog") <= SurfaceValue("support") {
		t.Fatal("catalog surface should outrank support chrome")
	}
}
