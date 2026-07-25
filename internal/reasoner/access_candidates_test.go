package reasoner

import "testing"

func TestAccessEndpointLooksOwnedObject(t *testing.T) {
	tests := []struct {
		name string
		ep   DiscoveredEndpoint
		want bool
	}{
		{
			name: "order id accepted",
			ep:   DiscoveredEndpoint{URL: "https://example.test/api/orders/42", Method: "GET", Path: "/api/orders/42"},
			want: true,
		},
		{
			name: "basket id accepted",
			ep:   DiscoveredEndpoint{URL: "https://example.test/rest/basket/7", Method: "GET", Path: "/rest/basket/7"},
			want: true,
		},
		{
			name: "challenge scoreboard rejected",
			ep:   DiscoveredEndpoint{URL: "https://example.test/api/Challenges/?name=Score%20Board", Method: "GET", Path: "/api/Challenges/", Params: []string{"name"}},
			want: false,
		},
		{
			name: "inventory quantity rejected",
			ep:   DiscoveredEndpoint{URL: "https://example.test/api/Quantitys/1", Method: "GET", Path: "/api/Quantitys/1"},
			want: false,
		},
		{
			name: "generic unknown route rejected",
			ep:   DiscoveredEndpoint{URL: "https://example.test/api/unknownpath", Method: "GET", Path: "/api/unknownpath"},
			want: false,
		},
		{
			name: "body owner field accepted",
			ep:   DiscoveredEndpoint{URL: "https://example.test/api/items", Method: "POST", Path: "/api/items", BodyFields: []string{"ownerId"}},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := accessEndpointLooksOwnedObject(tt.ep); got != tt.want {
				t.Fatalf("accessEndpointLooksOwnedObject(%+v) = %v, want %v", tt.ep, got, tt.want)
			}
		})
	}
}

func TestValidatePlansRejectsAccessPlanForPublicMetaEndpoint(t *testing.T) {
	ev := Evidence{
		QueryEndpoints: []DiscoveredEndpoint{{
			URL:    "https://example.test/api/Challenges/?name=Score%20Board",
			Method: "GET",
			Path:   "/api/Challenges/",
			Params: []string{"name"},
		}},
		APIEndpoints: []DiscoveredEndpoint{{
			URL:    "https://example.test/api/orders/42",
			Method: "GET",
			Path:   "/api/orders/42",
		}},
	}
	plans := validatePlans([]ProbePlan{
		{
			Technique: "idor_sequential_id",
			Target:    ProbeTarget{URL: "https://example.test/api/Challenges/?name=Score%20Board", Method: "GET", Field: "id"},
			Payloads:  []string{"1", "2"},
			Confirmation: ConfirmationRule{
				StatusCodes:  []int{200},
				BodyContains: []string{"id"},
			},
			Confidence: 0.7,
		},
		{
			Technique: "idor_sequential_id",
			Target:    ProbeTarget{URL: "https://example.test/api/orders/42", Method: "GET", Field: "path"},
			Payloads:  []string{"41", "42"},
			Confirmation: ConfirmationRule{
				StatusCodes:  []int{200},
				BodyContains: []string{"order"},
			},
			Confidence: 0.7,
		},
	}, ev)
	if len(plans) != 1 {
		t.Fatalf("validated plans = %+v, want one owned-object plan", plans)
	}
	if plans[0].Target.URL != "https://example.test/api/orders/42" {
		t.Fatalf("kept target = %q", plans[0].Target.URL)
	}
}

func TestAccessCandidateRejectsHyphenatedConfigurationEndpoint(t *testing.T) {
	ep := DiscoveredEndpoint{
		URL:  "https://example.test/rest/admin/application-configuration/1",
		Path: "/rest/admin/application-configuration/1",
	}
	if accessEndpointLooksOwnedObject(ep) {
		t.Fatal("application-configuration endpoint was accepted as an owned-object access candidate")
	}
}

func TestEmptyPlanResponse(t *testing.T) {
	for _, content := range []string{"{}", "[]", `{"plans":[]}`, `{"result":[]}`, "null", "  "} {
		if !emptyPlanResponse(content) {
			t.Fatalf("emptyPlanResponse(%q) = false, want true", content)
		}
	}
	if emptyPlanResponse(`{"plans":[{"technique":"idor_sequential_id"}]}`) {
		t.Fatal("non-empty plans were treated as empty")
	}
}
