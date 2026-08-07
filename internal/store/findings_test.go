package store

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/ozzyw/aobtd/pkg/types"
)

func TestListFindingsRoundTripsAndSortsPersistedFindings(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "findings.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	scanID, err := db.CreateScan("https://example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}

	_, err = db.InsertFinding(scanID, types.Finding{
		Title:       "possible critical",
		Description: "later than confirmed despite severity",
		Severity:    types.SeverityCritical,
		Confidence:  types.ConfidencePossible,
		EndpointID:  "GET /maybe",
		TrafficIDs:  []int64{7, 8},
		Evidence:    "maybe",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.InsertFinding(scanID, types.Finding{
		Title:        "confirmed medium",
		Description:  "second confirmed issue",
		Severity:     types.SeverityMedium,
		Confidence:   types.ConfidenceConfirmed,
		EndpointID:   "POST /feedback",
		VulnType:     "validation",
		HypothesisID: "h-feedback",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.InsertFinding(scanID, types.Finding{
		Title:            "confirmed high",
		Description:      "first confirmed issue",
		Severity:         types.SeverityHigh,
		Confidence:       types.ConfidenceConfirmed,
		EndpointID:       "POST /login",
		TrafficIDs:       []int64{42},
		Evidence:         "bypass",
		Remediation:      "parameterize",
		VulnType:         "sqli",
		ParamName:        "email",
		Payload:          "' OR 1=1--",
		StepsToReproduce: "1. POST payload",
		Impact:           "account takeover",
	})
	if err != nil {
		t.Fatal(err)
	}

	got, err := db.ListFindings(scanID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("ListFindings() len = %d, want 3: %+v", len(got), got)
	}
	if got[0].Title != "confirmed high" || got[1].Title != "confirmed medium" || got[2].Title != "possible critical" {
		t.Fatalf("unexpected ordering: %q, %q, %q", got[0].Title, got[1].Title, got[2].Title)
	}
	if got[0].TrafficIDs[0] != 42 || got[0].VulnType != "sqli" || got[0].ParamName != "email" ||
		got[0].Payload == "" || got[0].Remediation == "" || got[0].Impact == "" {
		t.Fatalf("confirmed high did not round-trip structured fields: %+v", got[0])
	}
	if got[0].CreatedAt.IsZero() {
		t.Fatalf("CreatedAt was not parsed: %+v", got[0])
	}
}

func TestInsertFindingMergesIndependentConfirmedDuplicates(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "findings.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}

	firstID, err := db.InsertFinding(scanID, types.Finding{
		Title:       "IDOR — /rest/basket/{id} exposes other users' resources",
		Description: "first specialist confirmation",
		Severity:    types.SeverityHigh,
		Confidence:  types.ConfidenceConfirmed,
		EndpointID:  "GET /rest/basket/NaN",
		TrafficIDs:  []int64{10},
		Evidence:    "basket 2 was readable",
		VulnType:    "idor",
	})
	if err != nil {
		t.Fatal(err)
	}
	secondID, err := db.InsertFinding(scanID, types.Finding{
		Title:            "IDOR — /rest/basket/{id} exposes other users' resources [via AccessControlReasoner]",
		Description:      "a richer second specialist confirmation with ownership comparison",
		Severity:         types.SeverityCritical,
		Confidence:       types.ConfidenceConfirmed,
		EndpointID:       "GET /rest/basket/{id}",
		TrafficIDs:       []int64{11, 10},
		Evidence:         "basket 3 was also readable by the same principal",
		VulnType:         "broken_object_level_authorization",
		StepsToReproduce: "1. Login\n2. Change the basket id",
		HypothesisID:     "h-idor",
	})
	if err != nil {
		t.Fatal(err)
	}
	if secondID != firstID {
		t.Fatalf("duplicate IDs differ: first=%d second=%d", firstID, secondID)
	}

	got, err := db.ListFindings(scanID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("confirmed duplicates produced %d rows: %+v", len(got), got)
	}
	f := got[0]
	if f.EndpointID != "GET /rest/basket/{id}" {
		t.Fatalf("endpoint = %q, want canonical template", f.EndpointID)
	}
	if f.Severity != types.SeverityCritical {
		t.Fatalf("severity = %q, want strongest confirmation", f.Severity)
	}
	if len(f.TrafficIDs) != 2 || f.TrafficIDs[0] != 10 || f.TrafficIDs[1] != 11 {
		t.Fatalf("traffic IDs were not merged: %+v", f.TrafficIDs)
	}
	if !strings.Contains(f.Evidence, "basket 2") || !strings.Contains(f.Evidence, "basket 3") {
		t.Fatalf("independent evidence was not preserved: %q", f.Evidence)
	}
	if f.StepsToReproduce == "" || f.HypothesisID != "h-idor" {
		t.Fatalf("structured detail was not enriched: %+v", f)
	}

	thirdID, err := db.InsertFinding(scanID, types.Finding{
		Title:       "IDOR — https://example.test/rest/basket/{id} exposes other users' resources",
		Description: "confirmation that only carried the endpoint in the title",
		Severity:    types.SeverityHigh,
		Confidence:  types.ConfidenceConfirmed,
		TrafficIDs:  []int64{12},
		VulnType:    "idor",
	})
	if err != nil {
		t.Fatal(err)
	}
	if thirdID != firstID {
		t.Fatalf("title-derived endpoint duplicate IDs differ: first=%d third=%d", firstID, thirdID)
	}
}

func TestInsertFindingMergesLoginBypassAcrossReasoners(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "findings.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}

	firstID, err := db.InsertFinding(scanID, types.Finding{
		Title:       "SQL injection login bypass on /rest/user/login (payload: email-quote-dashdash)",
		Description: "analyzer confirmation",
		Severity:    types.SeverityCritical,
		Confidence:  types.ConfidenceConfirmed,
		EndpointID:  "POST /rest/user/login",
		VulnType:    "sqli",
		ParamName:   "email",
		TrafficIDs:  []int64{21},
		Evidence:    "email field bypassed authentication",
	})
	if err != nil {
		t.Fatal(err)
	}
	secondID, err := db.InsertFinding(scanID, types.Finding{
		Title:            "SQL injection login bypass at https://example.test/rest/user/login [via AuthReasoner]",
		Description:      "reasoner confirmation",
		Severity:         types.SeverityCritical,
		Confidence:       types.ConfidenceConfirmed,
		EndpointID:       "POST https://example.test/rest/user/login",
		VulnType:         "sql_injection",
		TrafficIDs:       []int64{22},
		Evidence:         "auth reasoner reproduced the bypass",
		StepsToReproduce: "1. Submit SQLi payload to login",
	})
	if err != nil {
		t.Fatal(err)
	}
	if secondID != firstID {
		t.Fatalf("login bypass duplicate IDs differ: first=%d second=%d", firstID, secondID)
	}

	got, err := db.ListFindings(scanID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("login bypass duplicates produced %d rows: %+v", len(got), got)
	}
	f := got[0]
	if len(f.TrafficIDs) != 2 || !strings.Contains(f.Evidence, "auth reasoner") || f.ParamName != "email" {
		t.Fatalf("login bypass duplicate did not merge details: %+v", f)
	}
}

func TestInsertFindingMergesIDORCollectionAndItemEndpoint(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "findings.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}

	firstID, err := db.InsertFinding(scanID, types.Finding{
		Title:       "IDOR — /api/Addresss exposes other users' resources",
		Description: "collection endpoint confirmation",
		Severity:    types.SeverityHigh,
		Confidence:  types.ConfidenceConfirmed,
		EndpointID:  "GET /api/Addresss",
		VulnType:    "idor",
		TrafficIDs:  []int64{41},
	})
	if err != nil {
		t.Fatal(err)
	}
	secondID, err := db.InsertFinding(scanID, types.Finding{
		Title:       "IDOR confirmed on /api/addresss/{id}",
		Description: "item endpoint confirmation",
		Severity:    types.SeverityCritical,
		Confidence:  types.ConfidenceConfirmed,
		EndpointID:  "GET /api/addresss/{id}",
		VulnType:    "broken_object_level_authorization",
		TrafficIDs:  []int64{42},
	})
	if err != nil {
		t.Fatal(err)
	}
	if secondID != firstID {
		t.Fatalf("collection/item duplicate IDs differ: first=%d second=%d", firstID, secondID)
	}
	got, err := db.ListFindings(scanID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("collection/item duplicates produced %d rows: %+v", len(got), got)
	}
	if got[0].Severity != types.SeverityCritical {
		t.Fatalf("severity = %q, want critical", got[0].Severity)
	}
}

func TestInsertFindingMergesRecoveredObjectAccessAndJWTValidationRootCauses(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "findings-root-cause.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}

	id1, err := db.InsertFinding(scanID, types.Finding{
		Title:    "Malformed object ID recovered into accessible endpoint",
		Severity: types.SeverityHigh, Confidence: types.ConfidenceConfirmed,
		EndpointID: "GET /rest/basket/6", VulnType: "broken_object_access_recovered_id",
		Evidence: "basket 6 returned another owner's object",
	})
	if err != nil {
		t.Fatal(err)
	}
	id2, err := db.InsertFinding(scanID, types.Finding{
		Title:    "IDOR confirmed on /rest/basket/{id}",
		Severity: types.SeverityHigh, Confidence: types.ConfidenceConfirmed,
		EndpointID: "GET /rest/basket/{id}", VulnType: "idor",
		Evidence: "adjacent basket returned distinct owner data",
	})
	if err != nil || id2 != id1 {
		t.Fatalf("IDOR root cause did not merge: ids=%d/%d err=%v", id1, id2, err)
	}

	jwt1, err := db.InsertFinding(scanID, types.Finding{
		Title:    "JWT alg=none accepted at /rest/user/whoami",
		Severity: types.SeverityCritical, Confidence: types.ConfidenceConfirmed,
		EndpointID: "GET /rest/user/whoami", VulnType: "jwt_unsigned",
	})
	if err != nil {
		t.Fatal(err)
	}
	jwt2, err := db.InsertFinding(scanID, types.Finding{
		Title:    "JWT alg:none accepted at /rest/user/authentication-details",
		Severity: types.SeverityCritical, Confidence: types.ConfidenceConfirmed,
		EndpointID: "GET /rest/user/authentication-details", VulnType: "jwt_unsigned",
	})
	if err != nil || jwt2 != jwt1 {
		t.Fatalf("JWT verifier root cause did not merge: ids=%d/%d err=%v", jwt1, jwt2, err)
	}
}

func TestInsertFindingMergesQueryParamFromEndpoint(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "findings.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}

	firstID, err := db.InsertFinding(scanID, types.Finding{
		Title:       "SQL Injection in 'q' parameter (baseline-diff)",
		Description: "verifier found differential behavior",
		Severity:    types.SeverityHigh,
		Confidence:  types.ConfidenceConfirmed,
		EndpointID:  "GET /rest/products/search",
		VulnType:    "sqli",
		ParamName:   "q",
		TrafficIDs:  []int64{31},
	})
	if err != nil {
		t.Fatal(err)
	}
	secondID, err := db.InsertFinding(scanID, types.Finding{
		Title:       `SQL injection in "q" parameter on https://example.test/rest/products/search?q= [via InjectionReasoner]`,
		Description: "reasoner confirmed the same query parameter",
		Severity:    types.SeverityHigh,
		Confidence:  types.ConfidenceConfirmed,
		EndpointID:  "GET https://example.test/rest/products/search?q=",
		VulnType:    "sqli",
		TrafficIDs:  []int64{32},
	})
	if err != nil {
		t.Fatal(err)
	}
	if secondID != firstID {
		t.Fatalf("query-param duplicate IDs differ: first=%d second=%d", firstID, secondID)
	}
}

func TestInsertFindingKeepsPossibleHypothesesAndDistinctHeadersSeparate(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "findings.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range []types.Finding{
		{Title: "Hypothesis — ownership may be missing", Description: "idea one", Severity: types.SeverityHigh, Confidence: types.ConfidencePossible, EndpointID: "GET /orders/{id}", VulnType: "idor"},
		{Title: "Hypothesis — role checks may be missing", Description: "idea two", Severity: types.SeverityHigh, Confidence: types.ConfidencePossible, EndpointID: "GET /orders/{id}", VulnType: "idor"},
		{Title: "Missing security header: content-security-policy", Description: "header", Severity: types.SeverityLow, Confidence: types.ConfidenceConfirmed},
		{Title: "Missing security header: referrer-policy", Description: "header", Severity: types.SeverityLow, Confidence: types.ConfidenceConfirmed},
	} {
		if _, err := db.InsertFinding(scanID, f); err != nil {
			t.Fatal(err)
		}
	}
	got, err := db.ListFindings(scanID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("distinct beliefs/issues collapsed unexpectedly: %+v", got)
	}
}
