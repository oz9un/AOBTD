package reasoner

import (
	"context"
	"testing"
)

func TestAccessReasonerDeterministicIDORFallbackWithoutLLM(t *testing.T) {
	r := NewAccessReasoner(nil, nil)
	ev := Evidence{
		ScanID: 1,
		Target: "https://example.test",
		APIEndpoints: []DiscoveredEndpoint{
			{
				URL:    "https://example.test/api/orders/7",
				Method: "GET",
				Path:   "/api/orders/7",
			},
		},
	}

	plans, usage, err := r.Apply(context.Background(), ev)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if usage.InputTokens != 0 || usage.OutputTokens != 0 {
		t.Fatalf("usage = %+v, want zero without LLM", usage)
	}
	if len(plans) != 1 {
		t.Fatalf("plans = %+v, want one deterministic IDOR plan", plans)
	}
	p := plans[0]
	if p.Technique != "idor_sequential_id" || p.Target.Field != "path" ||
		p.Target.URL != "https://example.test/api/orders/7" ||
		p.SourceReasoner != "AccessReasoner" {
		t.Fatalf("unexpected plan: %+v", p)
	}
	if len(p.Payloads) < 2 || p.Payloads[0] != "8" || p.Payloads[1] != "6" {
		t.Fatalf("payloads = %v, want adjacent identifiers around 7", p.Payloads)
	}
	if len(p.Confirmation.StatusCodes) != 1 || p.Confirmation.StatusCodes[0] != 200 ||
		p.Confirmation.MinBodyBytes < 20 {
		t.Fatalf("confirmation too weak/incorrect: %+v", p.Confirmation)
	}
}

func TestAccessReasonerDeterministicIDORFallbackUsesQueryOwnerID(t *testing.T) {
	r := NewAccessReasoner(nil, nil)
	ev := Evidence{
		ScanID: 1,
		Target: "https://example.test",
		QueryEndpoints: []DiscoveredEndpoint{
			{
				URL:    "https://example.test/api/orders?userId=7",
				Method: "GET",
				Path:   "/api/orders",
				Params: []string{"userId"},
			},
		},
	}

	plans, _, err := r.Apply(context.Background(), ev)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(plans) != 1 {
		t.Fatalf("plans = %+v, want query-id fallback plan", plans)
	}
	if plans[0].Target.Field != "userId" || plans[0].Payloads[0] != "8" {
		t.Fatalf("unexpected query-id plan: %+v", plans[0])
	}
}

func TestAccessReasonerDeterministicIDORFallbackCarriesRecoveredAuthHeaders(t *testing.T) {
	r := NewAccessReasoner(nil, nil)
	ev := Evidence{
		ScanID: 1,
		Target: "https://example.test",
		APIEndpoints: []DiscoveredEndpoint{
			{
				URL:         "https://example.test/rest/basket/1",
				Method:      "GET",
				Path:        "/rest/basket/1",
				AuthHeaders: map[string]string{"Authorization": "Bearer observed"},
			},
		},
	}

	plans, _, err := r.Apply(context.Background(), ev)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(plans) != 1 {
		t.Fatalf("plans = %+v, want recovered basket IDOR plan", plans)
	}
	if got := plans[0].Target.Headers["Authorization"]; got != "Bearer observed" {
		t.Fatalf("Authorization header = %q, want recovered bearer", got)
	}
}

func TestAccessReasonerAppendsDeterministicOwnedObjectPlansAlongsideLLM(t *testing.T) {
	mock := &mockProvider{content: `{
		"plans": [{
			"technique": "idor_sequential_id",
			"target": {"url": "https://example.test/api/Feedbacks/?id=1", "method": "GET", "field": "id"},
			"payloads": ["1", "2"],
			"confirmation": {"status_codes": [200], "min_body_bytes": 20},
			"rationale": "model-selected feedback id probe",
			"confidence": 0.75
		}]
	}`, inTokens: 100, outTokens: 20}
	r := NewAccessReasoner(mock, nil)
	ev := Evidence{
		ScanID: 1,
		Target: "https://example.test",
		APIEndpoints: []DiscoveredEndpoint{
			{
				URL:         "https://example.test/rest/basket/1",
				Method:      "GET",
				Path:        "/rest/basket/1",
				AuthHeaders: map[string]string{"Authorization": "Bearer observed"},
			},
		},
		QueryEndpoints: []DiscoveredEndpoint{
			{
				URL:    "https://example.test/api/Feedbacks/?id=1",
				Method: "GET",
				Path:   "/api/Feedbacks/",
				Params: []string{"id"},
			},
		},
	}

	plans, _, err := r.Apply(context.Background(), ev)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(plans) < 2 {
		t.Fatalf("plans = %+v, want LLM plan plus deterministic recovered basket plan", plans)
	}
	var sawBasket bool
	for _, plan := range plans {
		if plan.Target.URL == "https://example.test/rest/basket/1" {
			sawBasket = true
			if got := plan.Target.Headers["Authorization"]; got != "Bearer observed" {
				t.Fatalf("basket Authorization = %q, want recovered bearer", got)
			}
		}
	}
	if !sawBasket {
		t.Fatalf("plans = %+v, missing deterministic recovered basket plan", plans)
	}
}

func TestAccessReasonerDeterministicIDORFallbackRejectsPublicCatalog(t *testing.T) {
	r := NewAccessReasoner(nil, nil)
	ev := Evidence{
		ScanID: 1,
		Target: "https://example.test",
		APIEndpoints: []DiscoveredEndpoint{
			{
				URL:    "https://example.test/api/products/7",
				Method: "GET",
				Path:   "/api/products/7",
			},
		},
	}

	plans, _, err := r.Apply(context.Background(), ev)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(plans) != 0 {
		t.Fatalf("public catalog endpoint produced access plan: %+v", plans)
	}
}
