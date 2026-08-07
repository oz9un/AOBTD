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

func TestParseActionRecoversMiniMaxDroppedNavigatePrefix(t *testing.T) {
	tests := []string{
		`"url": "http://juice-shop.test:3000/#/login",
  "reason": "Login page is a primary authentication attack surface."`,
		`navigate",
  "url": "http://juice-shop.test:3000/#/contact",
  "selector": "",
  "value": "",
  "reason": "Navigate to the contact workflow."`,
		`"navigate",
  "url": "http://juice-shop.test:3000/#/score-board",
  "reason": "Open the observed score board route."`,
		`": "navigate",
  "url": "http://127.0.0.1:4280/vulnerabilities/xss_r/",
  "reason": "XSS Reflected is a distinct vulnerability surface."`,
		`action": "navigate",
  "url": "http://127.0.0.1:4280/instructions.php",
  "reason": "Navigate to the instructions page to ground the application identity."`,
	}
	for _, raw := range tests {
		action, err := ParseAction(raw)
		if err != nil {
			t.Fatalf("ParseAction(%q) error = %v", raw, err)
		}
		if action.Action != "navigate" || action.URL == "" || action.Reason == "" {
			t.Fatalf("unexpected recovered action: %+v", action)
		}
	}
}

func TestParseActionRecoversMiniMaxDroppedSelectorPrefix(t *testing.T) {
	tests := []struct {
		raw        string
		wantAction string
		wantValue  string
	}{
		{
			raw: `"selector": "#navbarAccount",
  "reason": "Clicking Account opens the login and registration dialog.",
  "question": ""
})`,
			wantAction: "click",
		},
		{
			raw: `{"selector": "#searchQuery",
  "value": "aobtd-test",
  "reason": "Fill the observed search field."
})`,
			wantAction: "fill",
			wantValue:  "aobtd-test",
		},
	}
	for _, tt := range tests {
		action, err := ParseAction(tt.raw)
		if err != nil {
			t.Fatalf("ParseAction(%q) error = %v", tt.raw, err)
		}
		if action.Action != tt.wantAction || action.Selector == "" ||
			action.Value != tt.wantValue || action.Reason == "" {
			t.Fatalf("unexpected recovered action: %+v", action)
		}
	}
}

func TestParseActionDoesNotInferNavigateFromArbitraryURLField(t *testing.T) {
	raw := `The next page might be useful: "url":"https://example.test/admin"`
	if action, err := ParseAction(raw); err == nil {
		t.Fatalf("ParseAction() = %+v, want error", action)
	}
}

func TestParseActionDoesNotInferSelectorActionFromProse(t *testing.T) {
	raw := `The likely account control has "selector":"#navbarAccount".`
	if action, err := ParseAction(raw); err == nil {
		t.Fatalf("ParseAction() = %+v, want error", action)
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
