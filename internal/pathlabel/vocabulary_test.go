package pathlabel

import "testing"

func TestParseVocabResponseAcceptsFencedDoubleEscapedJSON(t *testing.T) {
	raw := "```json\n{\\\"site_type\\\":\\\"documentation platform\\\",\\\"stable_bff_prefixes\\\":[\\\"api\\\"],\\\"position_patterns\\\":[],\\\"variable_types\\\":{}}\n```"
	got, err := parseVocabResponse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.SiteType != "documentation platform" || len(got.StableBFFPrefixes) != 1 || got.StableBFFPrefixes[0] != "api" {
		t.Fatalf("parsed vocabulary = %+v", got)
	}
}

func TestParseVocabResponseRepairsMiniMaxDroppedOpeningBrace(t *testing.T) {
	raw := `"site_type": "OWASP Juice Shop",
  "stable_bff_prefixes": ["/api", "/rest"],
  "position_patterns": [],
  "variable_types": {}
}`
	got, err := parseVocabResponse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.SiteType != "OWASP Juice Shop" || len(got.StableBFFPrefixes) != 2 {
		t.Fatalf("parsed vocabulary = %+v", got)
	}
}
