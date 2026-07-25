package agent

import (
	"testing"

	"github.com/ozzyw/aobtd/internal/policy"
)

func TestCrawlerDoesNotOfferCredentialPromptUnderRecon(t *testing.T) {
	crawler := &CrawlerAgent{testingAuthority: policy.AuthorityRecon}
	if crawler.shouldSurfaceLoginPrompt() {
		t.Fatal("Recon crawler offered an interactive credential prompt")
	}
	crawler.testingAuthority = policy.AuthorityActive
	if !crawler.shouldSurfaceLoginPrompt() {
		t.Fatal("Active crawler lost the optional credential prompt")
	}
	crawler.authAlreadyConfigured = true
	if crawler.shouldSurfaceLoginPrompt() {
		t.Fatal("crawler prompted even though authentication was preconfigured")
	}
}
