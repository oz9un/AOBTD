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
