package protection

import (
	"testing"

	"github.com/ozzyw/aobtd/pkg/types"
)

func TestClassifyResponseRequiresStrongProtectionEvidence(t *testing.T) {
	challenge := types.CapturedResponse{
		StatusCode: 403, ContentType: "text/html; charset=utf-8",
		Headers: map[string]string{"Server": "cloudflare", "CF-Ray": "volatile-ray-id"},
		Body:    []byte(`<html><title>Just a moment...</title><script src="/cdn-cgi/challenge-platform/x"></script><p>Enable JavaScript and cookies to continue</p></html>`),
	}
	first := ClassifyResponse(challenge)
	if !first.IsInterstitial || first.Vendor != "cloudflare" || first.Fingerprint == "" {
		t.Fatalf("challenge evidence = %+v", first)
	}
	challenge.Headers["CF-Ray"] = "different-ray-id"
	if second := ClassifyResponse(challenge); second.Fingerprint != first.Fingerprint {
		t.Fatalf("volatile ray id changed shape: first=%+v second=%+v", first, second)
	}

	for _, response := range []types.CapturedResponse{
		{StatusCode: 403, ContentType: "text/html", Body: []byte(`<h1>Members only</h1>`)},
		{StatusCode: 200, ContentType: "application/json", Body: []byte(`{"challenge":"weekly coding challenge"}`)},
		{StatusCode: 200, ContentType: "text/html", Body: []byte(`<h1>Captcha product catalog</h1>`)},
	} {
		if evidence := ClassifyResponse(response); evidence.IsInterstitial {
			t.Fatalf("application response became protection evidence: %+v => %+v", response, evidence)
		}
	}
}

func TestSummarizeTrafficPreservesRecoveredApplicationAndServerErrors(t *testing.T) {
	interstitial := types.TrafficEntry{Response: types.CapturedResponse{
		StatusCode: 403, ContentType: "text/html", Headers: map[string]string{"Server": "cloudflare"},
		Body: []byte(`<title>Just a moment...</title><p>Performing security verification</p>`),
	}}
	application := types.TrafficEntry{Response: types.CapturedResponse{
		StatusCode: 200, ContentType: "text/html", Body: []byte(`<title>Popular reviews</title><main>Member reviews</main>`),
	}}
	serverError := types.TrafficEntry{Response: types.CapturedResponse{
		StatusCode: 503, ContentType: "text/html", Headers: map[string]string{"Server": "cloudflare"},
		Body: []byte(`<title>Just a moment...</title><p>Performing security verification</p>`),
	}}

	challengeOnly := SummarizeTraffic([]types.TrafficEntry{interstitial, interstitial})
	if !challengeOnly.ChallengeOnly || challengeOnly.InterstitialResponses != 2 || len(challengeOnly.Fingerprints) != 1 {
		t.Fatalf("challenge-only summary = %+v", challengeOnly)
	}
	recovered := SummarizeTraffic([]types.TrafficEntry{interstitial, application})
	if recovered.ChallengeOnly || !recovered.RecoveredApplication || recovered.ApplicationResponses != 1 {
		t.Fatalf("recovered application summary = %+v", recovered)
	}
	failure := SummarizeTraffic([]types.TrafficEntry{serverError})
	if failure.ChallengeOnly || failure.ServerErrors != 1 {
		t.Fatalf("server-error summary = %+v", failure)
	}
}
