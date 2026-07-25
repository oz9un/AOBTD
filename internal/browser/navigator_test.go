package browser

import "testing"

func TestParseActionAcceptsFirstCompleteJSONObject(t *testing.T) {
	raw := `{"action":"click","selector":"#navbarAccount","reason":"open account"}
{`
	action, err := ParseAction(raw)
	if err != nil {
		t.Fatalf("ParseAction() error = %v", err)
	}
	if action.Action != "click" || action.Selector != "#navbarAccount" {
		t.Fatalf("unexpected action: %+v", action)
	}
}

func TestParseActionRecoversCompletedNavigateFromTruncatedReason(t *testing.T) {
	raw := `{"action":"navigate","url":"https://www.nasa.gov/multimedia/","reason":"Inspect a distinct media surface that may reveal`
	action, err := ParseAction(raw)
	if err != nil {
		t.Fatalf("ParseAction() error = %v", err)
	}
	if action.Action != "navigate" || action.URL != "https://www.nasa.gov/multimedia/" {
		t.Fatalf("unexpected recovered action: %+v", action)
	}
}

func TestParseActionDoesNotRecoverTruncatedURL(t *testing.T) {
	raw := `{"action":"navigate","url":"https://www.nasa.gov/multi`
	if action, err := ParseAction(raw); err == nil {
		t.Fatalf("ParseAction() = %+v, want error", action)
	}
}

func TestParseActionDoesNotRecoverUnknownAction(t *testing.T) {
	raw := `{"action":"execute","url":"https://www.nasa.gov/","reason":"truncated`
	if action, err := ParseAction(raw); err == nil {
		t.Fatalf("ParseAction() = %+v, want error", action)
	}
}

func TestShouldCaptureNavigatorHrefKeepsHashRoutes(t *testing.T) {
	tests := []struct {
		href string
		want bool
	}{
		{href: "", want: false},
		{href: "javascript:void(0)", want: false},
		{href: "#", want: false},
		{href: "#section", want: false},
		{href: "#/basket", want: true},
		{href: "#!/admin", want: true},
		{href: "/account", want: true},
		{href: "https://target.test/#/search", want: true},
	}
	for _, tt := range tests {
		if got := shouldCaptureNavigatorHref(tt.href); got != tt.want {
			t.Fatalf("shouldCaptureNavigatorHref(%q)=%v, want %v", tt.href, got, tt.want)
		}
	}
}
