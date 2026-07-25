package agent

import (
	"strings"
	"testing"

	"github.com/ozzyw/aobtd/internal/browser"
	"github.com/ozzyw/aobtd/internal/policy"
	"github.com/ozzyw/aobtd/internal/workflow"
)

func TestRepeatedNavigatorActionRejectsSameActionOnSamePage(t *testing.T) {
	seen := make(map[string]struct{})
	action := &browser.NavigatorAction{Action: "click", Selector: "#navbarAccount"}

	if repeatedNavigatorAction(seen, action, "http://target.test/") {
		t.Fatal("first action was reported as repeated")
	}
	if !repeatedNavigatorAction(seen, action, "http://target.test/") {
		t.Fatal("identical action on the same page was not rejected")
	}
}

func TestNavigatorDefaultStepBudgetLeavesRoomForFormMacro(t *testing.T) {
	nav := NewNavigatorAgent(nil, nil, nil, nil, nil, nil, 0, nil, policy.AuthorityActive, nil)
	if nav.maxSteps != 10 {
		t.Fatalf("maxSteps=%d, want 10", nav.maxSteps)
	}
}

func TestNavigatorNarrationUsesVisibleControlLabel(t *testing.T) {
	state := &browser.PageState{
		URL: "https://app.example.test/",
		Buttons: []browser.ButtonInfo{{
			Text: "Categories", Selector: "#categories", Type: "button",
		}},
	}
	action := &browser.NavigatorAction{
		Action: "click", Selector: "#categories", Reason: "reveal a distinct navigation area",
	}
	message := navigatorPlanNarration(action, state, 2, 8)
	for _, want := range []string{"UI step 2/8", `Click "Categories"`, "distinct navigation area"} {
		if !strings.Contains(message, want) {
			t.Fatalf("navigator narration missing %q in %q", want, message)
		}
	}
}

func TestNavigatorResultNarrationReportsNavigation(t *testing.T) {
	action := &browser.NavigatorAction{Action: "navigate", URL: "https://app.example.test/settings"}
	message := navigatorResultNarration(action, nil,
		"https://app.example.test/", "https://app.example.test/settings")
	if !strings.Contains(message, "browser moved to https://app.example.test/settings") {
		t.Fatalf("navigator result narration lost destination: %q", message)
	}
}

func TestReconNavigatorUsesSmallerReadOnlyStepBudget(t *testing.T) {
	nav := NewNavigatorAgent(nil, nil, nil, nil, nil, nil, 0, nil, policy.AuthorityRecon, nil)
	if nav.maxSteps != 6 {
		t.Fatalf("recon maxSteps=%d, want 6", nav.maxSteps)
	}
}

func TestReconNavigatorNeverPausesForOperatorGuidance(t *testing.T) {
	if navigatorMayAskHuman(policy.AuthorityRecon) {
		t.Fatal("Recon navigator may not block a scan on ask_human")
	}
	if !navigatorMayAskHuman(policy.AuthorityActive) {
		t.Fatal("active navigator unexpectedly lost operator escalation")
	}
}

func TestNavigatorAvoidsSeededNavigationTargets(t *testing.T) {
	nav := NewNavigatorAgent(nil, nil, nil, nil, NewSharedState("http://target.test/"), nil, 0, nil, policy.AuthorityActive, nil)
	nav.SetAvoidNavigationTargets([]string{"http://target.test/#/login"})

	target, seen := nav.navigationTargetAlreadyExplored("#/login", "http://target.test/")
	if !seen {
		t.Fatal("expected hash-route navigation target to be recognized as already explored")
	}
	if target != "http://target.test/#/login" {
		t.Fatalf("target = %q, want canonical hash route", target)
	}
	if _, seen := nav.navigationTargetAlreadyExplored("#/basket", "http://target.test/"); seen {
		t.Fatal("different hash-route was treated as already explored")
	}
}

func TestNavigatorVisitedTargetsFeedAvoidancePrompt(t *testing.T) {
	nav := NewNavigatorAgent(nil, nil, nil, nil, NewSharedState("http://target.test/"), nil, 0, nil, policy.AuthorityActive, nil)
	nav.rememberNavigationTarget("http://target.test/#/login", "")
	hint := renderNavigatorAvoidance(nav.navigationAvoidanceSnapshot(8))
	if !strings.Contains(hint, "Already explored navigator routes") || !strings.Contains(hint, "http://target.test/#/login") {
		t.Fatalf("avoidance hint missing visited route: %q", hint)
	}
}

func TestNavigatorRemembersRequestedRouteAcrossRedirect(t *testing.T) {
	nav := NewNavigatorAgent(nil, nil, nil, nil, NewSharedState("https://target.test/"), nil, 0, nil, policy.AuthorityRecon, nil)

	// Mirrors a successful navigate to /my-account that lands on /login.
	nav.rememberNavigationTarget("/my-account", "https://target.test/")
	nav.rememberNavigationTarget("https://target.test/login", "https://target.test/")

	if target, seen := nav.navigationTargetAlreadyExplored("/my-account", "https://target.test/login"); !seen {
		t.Fatalf("redirect source %q was not remembered across the landing page", target)
	}
	if target, seen := nav.navigationTargetAlreadyExplored("/login", "https://target.test/"); !seen {
		t.Fatalf("redirect destination %q was not remembered", target)
	}
}

func TestReconNavigatorDoesNotActivateFormsOrAuthentication(t *testing.T) {
	state := &browser.PageState{
		Inputs: []browser.InputInfo{{Name: "email", Type: "email", Selector: "#email"}},
		Buttons: []browser.ButtonInfo{
			{Text: "Login", Selector: "#login", Type: "submit"},
			{Text: "Google ile devam et", Selector: "#google", Type: "button"},
			{Text: "Open menu", Selector: "#menu", Type: "button"},
		},
	}
	for _, action := range []*browser.NavigatorAction{
		{Action: "fill", Selector: "#email", Value: "test@example.test"},
		{Action: "submit", Selector: "#login"},
		{Action: "click", Selector: "#login"},
		{Action: "click", Selector: "#google"},
	} {
		if err := validateNavigatorActionForAuthority(action, state, policy.AuthorityRecon); err == nil {
			t.Fatalf("recon accepted workflow action: %+v", action)
		}
	}
	if err := validateNavigatorActionForAuthority(&browser.NavigatorAction{Action: "click", Selector: "#menu"}, state, policy.AuthorityRecon); err != nil {
		t.Fatalf("recon rejected read-only menu discovery: %v", err)
	}
	if err := validateNavigatorActionForAuthority(&browser.NavigatorAction{Action: "fill", Selector: "#email"}, state, policy.AuthorityActive); err != nil {
		t.Fatalf("active authority rejected safe form fill: %v", err)
	}
}

func TestReconNavigatorRequiresObservedNavigationTarget(t *testing.T) {
	state := &browser.PageState{
		URL: "https://target.test/",
		Links: []browser.LinkInfo{
			{Text: "Newest", Href: "/newest"},
			{Text: "Login", Href: "https://target.test/login?goto=news"},
		},
	}

	if err := validateNavigatorActionForAuthority(&browser.NavigatorAction{
		Action: "navigate",
		URL:    "https://target.test/newest",
	}, state, policy.AuthorityRecon); err != nil {
		t.Fatalf("observed absolute navigation rejected: %v", err)
	}
	if err := validateNavigatorActionForAuthority(&browser.NavigatorAction{
		Action: "navigate",
		URL:    "/login?goto=news",
	}, state, policy.AuthorityRecon); err != nil {
		t.Fatalf("observed relative navigation rejected: %v", err)
	}
	if err := validateNavigatorActionForAuthority(&browser.NavigatorAction{
		Action: "navigate",
		URL:    "https://target.test/admin/settings",
	}, state, policy.AuthorityRecon); err == nil {
		t.Fatal("recon accepted guessed navigation target")
	}
	if err := validateNavigatorActionForAuthority(&browser.NavigatorAction{
		Action: "navigate",
		URL:    "https://target.test/api",
	}, state, policy.AuthorityActive); err != nil {
		t.Fatalf("active authority should retain direct navigation freedom: %v", err)
	}
}

func TestReconNavigatorRetainsExactLinksAcrossSparsePages(t *testing.T) {
	nav := NewNavigatorAgent(nil, nil, nil, nil, NewSharedState("https://target.test/"), nil, 0, nil, policy.AuthorityRecon, nil)
	landing := &browser.PageState{
		URL: "https://target.test/",
		Links: []browser.LinkInfo{
			{Text: "Newest", Href: "/newest"},
			{Text: "Login", Href: "/login"},
		},
	}
	nav.observeNavigationTargets(landing)

	// Mirrors landing on a sparse auth page that no longer links to /newest.
	sparse := &browser.PageState{URL: "https://target.test/login"}
	if err := nav.validateActionForAuthority(&browser.NavigatorAction{
		Action: "navigate",
		URL:    "https://target.test/newest",
	}, sparse); err != nil {
		t.Fatalf("previously observed exact route rejected from sparse page: %v", err)
	}
	if err := nav.validateActionForAuthority(&browser.NavigatorAction{
		Action: "navigate",
		URL:    "https://target.test/admin",
	}, sparse); err == nil {
		t.Fatal("unobserved guessed route accepted from session memory")
	}
}

func TestReconNavigatorCarriesExactObservedLinksAcrossPhases(t *testing.T) {
	first := NewNavigatorAgent(nil, nil, nil, nil, NewSharedState("https://target.test/"), nil, 0, nil, policy.AuthorityRecon, nil)
	first.observeNavigationTargets(&browser.PageState{
		URL: "https://target.test/",
		Links: []browser.LinkInfo{
			{Text: "Reviews", Href: "/reviews/popular/"},
			{Text: "Vendor help", Href: "https://vendor.test/help"},
		},
	})

	second := NewNavigatorAgent(nil, nil, nil, nil, NewSharedState("https://target.test/"), nil, 0, nil, policy.AuthorityRecon, nil)
	engine, err := policy.New(policy.AuthorityRecon, []string{"https://target.test"})
	if err != nil {
		t.Fatal(err)
	}
	second.SetExecutionPolicy(engine, nil)
	second.SetObservedNavigationTargets(first.ObservedNavigationTargets())

	if err := second.validateActionForAuthority(&browser.NavigatorAction{Action: "navigate", URL: "https://target.test/reviews/popular/"}, &browser.PageState{URL: "https://target.test/sparse"}); err != nil {
		t.Fatalf("cross-phase exact route rejected: %v", err)
	}
	if got := second.ObservedNavigationTargets(); len(got) != 1 || got[0] != "https://target.test/reviews/popular/" {
		t.Fatalf("cross-phase observed routes = %v, want only in-scope application link", got)
	}
}

func TestNavigatorRequiresObservedAndInScopeNavigation(t *testing.T) {
	engine, err := policy.New(policy.AuthorityRecon, []string{"https://target.test"})
	if err != nil {
		t.Fatal(err)
	}
	var audited policy.Decision
	nav := NewNavigatorAgent(nil, nil, nil, nil, NewSharedState("https://target.test/"), nil, 0, nil, policy.AuthorityRecon, nil)
	nav.SetExecutionPolicy(engine, func(decision policy.Decision) { audited = decision })

	inScope := &browser.NavigatorAction{Action: "navigate", URL: "https://target.test/news"}
	if err := nav.authorizeNavigationAction(inScope); err != nil {
		t.Fatalf("in-scope GET rejected: %v", err)
	}
	outOfScope := &browser.NavigatorAction{Action: "navigate", URL: "https://docs.target.test/news"}
	if err := nav.authorizeNavigationAction(outOfScope); err == nil {
		t.Fatal("observed-but-out-of-scope navigation was accepted")
	}
	if audited.Code != policy.CodeOutOfScope || audited.TargetURL != outOfScope.URL {
		t.Fatalf("audit decision=%+v", audited)
	}
}

func TestNavigatorDecisionInventoryOmitsOutOfScopeLinks(t *testing.T) {
	engine, err := policy.New(policy.AuthorityRecon, []string{"https://target.test"})
	if err != nil {
		t.Fatal(err)
	}
	nav := NewNavigatorAgent(nil, nil, nil, nil, NewSharedState("https://target.test/"), nil, 0, nil, policy.AuthorityRecon, nil)
	nav.SetExecutionPolicy(engine, nil)
	state := &browser.PageState{
		URL: "https://target.test/",
		Links: []browser.LinkInfo{
			{Text: "News", Href: "/news"},
			{Text: "External docs", Href: "https://docs.target.test/"},
		},
	}

	nav.observeNavigationTargets(state)
	filtered := nav.navigationDecisionState(state)
	if len(filtered.Links) != 1 || filtered.Links[0].Href != "/news" {
		t.Fatalf("filtered links=%+v", filtered.Links)
	}
	hint := renderNavigatorObservedTargets(nav.observedNavigationSnapshot(8))
	if !strings.Contains(hint, "https://target.test/news") || strings.Contains(hint, "docs.target.test") {
		t.Fatalf("observed inventory leaked unauthorized route: %q", hint)
	}
	if len(state.Links) != 2 {
		t.Fatalf("decision projection mutated captured evidence: %+v", state.Links)
	}
}

func TestNavigatorDecisionInventoryOmitsChallengeVendorDetours(t *testing.T) {
	nav := NewNavigatorAgent(nil, nil, nil, nil, NewSharedState("https://target.test/"), nil, 0, nil, policy.AuthorityRecon, nil)
	state := &browser.PageState{
		URL: "https://target.test/",
		Links: []browser.LinkInfo{
			{Text: "Challenge help", Href: "/cdn-cgi/challenge-platform/help"},
			{Text: "Popular reviews", Href: "/reviews/popular/"},
		},
	}
	nav.observeNavigationTargets(state)
	filtered := nav.navigationDecisionState(state)
	if len(filtered.Links) != 1 || filtered.Links[0].Href != "/reviews/popular/" {
		t.Fatalf("challenge detour remained in decision inventory: %+v", filtered.Links)
	}
	hint := renderNavigatorObservedTargets(nav.observedNavigationSnapshot(8))
	if strings.Contains(hint, "cdn-cgi") || !strings.Contains(hint, "/reviews/popular/") {
		t.Fatalf("remembered target inventory = %q", hint)
	}
}

func TestNavigatorDecisionInventoryTreatsCatalogCategoryLabelAsTaxonomy(t *testing.T) {
	nav := NewNavigatorAgent(nil, nil, nil, nil, NewSharedState("https://books.test/"), nil, 0, nil, policy.AuthorityRecon, nil)
	state := &browser.PageState{
		URL: "https://books.test/",
		Links: []browser.LinkInfo{{
			Text: "Add a comment",
			Href: "/catalogue/category/books/add-a-comment_18/index.html",
		}},
	}

	filtered := nav.navigationDecisionState(state)
	if len(filtered.Links) != 1 {
		t.Fatalf("filtered links=%+v", filtered.Links)
	}
	label := filtered.Links[0].Text
	for _, want := range []string{"Catalog category", "Add a comment", "not evidence of an action or workflow"} {
		if !strings.Contains(label, want) {
			t.Fatalf("model-visible catalog label missing %q: %q", want, label)
		}
	}
	if state.Links[0].Text != "Add a comment" {
		t.Fatalf("decision projection mutated captured evidence: %+v", state.Links)
	}
}

func TestNavigatorDecisionInventoryOmitsAlreadyExploredRoutes(t *testing.T) {
	nav := NewNavigatorAgent(nil, nil, nil, nil, NewSharedState("https://app.test/"), nil, 0, nil, policy.AuthorityRecon, nil)
	nav.rememberNavigationTarget("https://app.test/catalogue/visited/", "")
	state := &browser.PageState{
		URL: "https://app.test/",
		Links: []browser.LinkInfo{
			{Text: "Home", Href: "/"},
			{Text: "Visited product", Href: "/catalogue/visited/"},
			{Text: "New product", Href: "/catalogue/new/"},
		},
	}

	filtered := nav.navigationDecisionState(state)
	if len(filtered.Links) != 1 || filtered.Links[0].Href != "/catalogue/new/" {
		t.Fatalf("model decision inventory retained current or explored route: %+v", filtered.Links)
	}
}

func TestReconDecisionInventorySuppressesTaxonomySiblingsAfterSurfaceSaturation(t *testing.T) {
	nav := NewNavigatorAgent(nil, nil, nil, nil, NewSharedState("https://shop.test/"), nil, 0, nil, policy.AuthorityRecon, nil)
	nav.rememberNavigatorSurface("https://shop.test/catalogue/", "Product catalog", "catalog-list")
	nav.rememberNavigatorSurface("https://shop.test/catalogue/widget/", "Product detail", "catalog-detail")
	state := &browser.PageState{
		URL: "https://shop.test/",
		Links: []browser.LinkInfo{
			{Text: "Another genre", Href: "/catalogue/category/books/history/"},
			{Text: "Popular reviews", Href: "/reviews/popular/"},
		},
	}

	filtered := nav.navigationDecisionState(state)
	if len(filtered.Links) != 1 || filtered.Links[0].Href != "/reviews/popular/" {
		t.Fatalf("saturated taxonomy sibling remained in model inventory: %+v", filtered.Links)
	}
}

func TestReconDecisionInventorySaturatesGenericTagTaxonomy(t *testing.T) {
	nav := NewNavigatorAgent(nil, nil, nil, nil, NewSharedState("https://quotes.test/"), nil, 0, nil, policy.AuthorityRecon, nil)
	nav.rememberNavigatorSurface("https://quotes.test/tag/humor/page/1/", "Humor", "tag-list-a")
	nav.rememberNavigatorSurface("https://quotes.test/tag/change/page/1/", "Change", "tag-list-b")
	state := &browser.PageState{
		URL: "https://quotes.test/author/albert/",
		Links: []browser.LinkInfo{
			{Text: "Another tag", Href: "/tag/life/page/1/"},
			{Text: "News", Href: "/news/"},
		},
	}

	filtered := nav.navigationDecisionState(state)
	if len(filtered.Links) != 1 || filtered.Links[0].Href != "/news/" {
		t.Fatalf("generic taxonomy saturation failed: %+v", filtered.Links)
	}
}

func TestReconDecisionInventoryUsesCrawlerSaturationAcrossNavigatorPhases(t *testing.T) {
	shared := NewSemanticSaturationState()
	for _, route := range []string{"humor", "change", "books"} {
		shared.Observe("https://quotes.test/tag/"+route+"/page/1/", "", "crawler-tag-template", "crawler", 200)
	}
	nav := NewNavigatorAgent(nil, nil, nil, nil, NewSharedState("https://quotes.test/"), nil, 0, nil, policy.AuthorityRecon, nil)
	nav.SetSemanticSaturation(shared)
	state := &browser.PageState{
		URL: "https://quotes.test/author/albert/",
		Links: []browser.LinkInfo{
			{Text: "Another tag", Href: "/tag/life/page/1/"},
			{Text: "Login category", Href: "/tag/login/page/1/"},
			{Text: "News", Href: "/news/"},
		},
	}
	filtered := nav.navigationDecisionState(state)
	if len(filtered.Links) != 2 || filtered.Links[0].Href == "/tag/life/page/1/" || filtered.Links[1].Href == "/tag/life/page/1/" {
		t.Fatalf("crawler-saturated taxonomy entered a fresh Navigator inventory: %+v", filtered.Links)
	}
	foundLogin := false
	for _, link := range filtered.Links {
		foundLogin = foundLogin || link.Href == "/tag/login/page/1/"
	}
	if !foundLogin {
		t.Fatalf("interesting login route was hidden by shared saturation: %+v", filtered.Links)
	}
	for _, link := range state.Links {
		nav.observedNavigationTargets[canonicalNavigatorURL(link.Href, state.URL)] = struct{}{}
	}
	observed := nav.observedNavigationSnapshot(8)
	for _, target := range observed {
		if strings.Contains(target, "/tag/life/") {
			t.Fatalf("crawler-saturated taxonomy leaked through the remembered exact-link list: %v", observed)
		}
	}
}

func TestNavigatorInitialCurrentPageCannotReenterDecisionInventory(t *testing.T) {
	nav := NewNavigatorAgent(nil, nil, nil, nil, NewSharedState("https://app.test/"), nil, 0, nil, policy.AuthorityRecon, nil)
	nav.rememberCurrentNavigationTarget("https://app.test/")
	state := &browser.PageState{
		URL: "https://app.test/author/albert/",
		Links: []browser.LinkInfo{
			{Text: "Home", Href: "/"},
			{Text: "News", Href: "/news/"},
		},
	}
	filtered := nav.navigationDecisionState(state)
	if len(filtered.Links) != 1 || filtered.Links[0].Href != "/news/" {
		t.Fatalf("initial landing page reentered model inventory: %+v", filtered.Links)
	}
}

func TestNavigatorDecisionInventoryPromotesSemanticDetailOverMenuOrder(t *testing.T) {
	engine, err := policy.New(policy.AuthorityRecon, []string{"https://shop.test"})
	if err != nil {
		t.Fatal(err)
	}
	nav := NewNavigatorAgent(nil, nil, nil, nil, NewSharedState("https://shop.test/"), nil, 0, nil, policy.AuthorityRecon, nil)
	nav.SetExecutionPolicy(engine, nil)
	state := &browser.PageState{URL: "https://shop.test/"}
	for i := 0; i < 50; i++ {
		state.Links = append(state.Links, browser.LinkInfo{Text: "Category", Href: "/category/" + string(rune('a'+i%26)) + "/page/" + string(rune('a'+i/26))})
	}
	state.Links = append(state.Links, browser.LinkInfo{Text: "Specific product", Href: "/catalogue/product/security-handbook_42/index.html"})

	filtered := nav.navigationDecisionState(state)
	if len(filtered.Links) != 24 {
		t.Fatalf("decision links=%d, want bounded 24", len(filtered.Links))
	}
	if filtered.Links[0].Text != "Specific product" {
		t.Fatalf("top decision link=%+v, want semantic detail", filtered.Links[0])
	}
}

func TestNavigatorLinkRankingRecognizesLocalizedCommerceRoutes(t *testing.T) {
	current := "https://shop.test/"
	basket := browser.LinkInfo{Text: "Sepetim", Href: "/sepetim"}
	account := browser.LinkInfo{Text: "Hesabım", Href: "/hesabim/siparislerim"}
	help := browser.LinkInfo{Text: "İletişim", Href: "/yardim/iletisim"}
	if navigatorLinkDecisionScore(basket, current) <= navigatorLinkDecisionScore(help, current) {
		t.Fatalf("localized basket did not outrank generic help: basket=%d help=%d", navigatorLinkDecisionScore(basket, current), navigatorLinkDecisionScore(help, current))
	}
	if navigatorLinkDecisionScore(account, current) <= navigatorLinkDecisionScore(help, current) {
		t.Fatalf("localized account/orders did not outrank generic help: account=%d help=%d", navigatorLinkDecisionScore(account, current), navigatorLinkDecisionScore(help, current))
	}
}

func TestNavigatorLinkRankingPrefersUnseenCoreJourney(t *testing.T) {
	nav := NewNavigatorAgent(nil, nil, nil, nil, NewSharedState("https://letterboxd.test/"), nil, 0, nil, policy.AuthorityRecon, nil)
	nav.rememberNavigatorSurface("https://letterboxd.test/settings/", "Account settings", "form:GET:password")
	nav.rememberNavigatorSurface("https://letterboxd.test/login/", "Log in", "form:POST:password")

	current := "https://letterboxd.test/"
	reviews := browser.LinkInfo{Text: "Popular reviews", Href: "/reviews/popular/this/week/"}
	settings := browser.LinkInfo{Text: "Account settings", Href: "/settings/profile/"}
	help := browser.LinkInfo{Text: "Help", Href: "/about/help/"}
	api := browser.LinkInfo{Text: "API beta", Href: "/api-beta/"}
	if nav.navigatorLinkDecisionScore(reviews, current) <= nav.navigatorLinkDecisionScore(settings, current) {
		t.Fatalf("unseen review surface did not outrank sampled settings: reviews=%d settings=%d",
			nav.navigatorLinkDecisionScore(reviews, current), nav.navigatorLinkDecisionScore(settings, current))
	}
	if nav.navigatorLinkDecisionScore(reviews, current) <= nav.navigatorLinkDecisionScore(help, current) {
		t.Fatalf("core review journey did not outrank help chrome: reviews=%d help=%d",
			nav.navigatorLinkDecisionScore(reviews, current), nav.navigatorLinkDecisionScore(help, current))
	}
	if nav.navigatorLinkDecisionScore(reviews, current) <= nav.navigatorLinkDecisionScore(api, current) {
		t.Fatalf("core review journey did not outrank generic API adjunct under Recon: reviews=%d api=%d",
			nav.navigatorLinkDecisionScore(reviews, current), nav.navigatorLinkDecisionScore(api, current))
	}
}

func TestNavigatorReconPromptPrioritizesApplicationUnderstanding(t *testing.T) {
	reconPrompt := navigatorSystemPromptForAuthority(policy.AuthorityRecon)
	for _, contract := range []string{
		"primary public business objects and human journeys",
		"Sample at most one representative authentication/account surface",
		"priority order never authorizes",
	} {
		if !strings.Contains(reconPrompt, contract) {
			t.Fatalf("Recon navigator prompt missing %q", contract)
		}
	}
	if strings.Contains(navigatorSystemPromptForAuthority(policy.AuthorityActive), "RECON APPLICATION-UNDERSTANDING OVERRIDE") {
		t.Fatal("Active navigator unexpectedly received the Recon-only priority override")
	}
}

func TestNavigatorObservedSnapshotUsesNoveltyBeforeAlphabeticalOrder(t *testing.T) {
	nav := NewNavigatorAgent(nil, nil, nil, nil, NewSharedState("https://letterboxd.test/"), nil, 0, nil, policy.AuthorityRecon, nil)
	nav.rememberNavigatorSurface("https://letterboxd.test/account/", "Account", "form:POST:password")
	nav.observeNavigationTargets(&browser.PageState{
		URL: "https://letterboxd.test/",
		Links: []browser.LinkInfo{
			{Text: "Account profile", Href: "/account/profile/"},
			{Text: "Popular reviews", Href: "/reviews/popular/this/week/"},
		},
	})

	got := nav.observedNavigationSnapshot(8)
	if len(got) != 2 || got[0] != "https://letterboxd.test/reviews/popular/this/week/" {
		t.Fatalf("novelty-ranked remembered links = %#v", got)
	}
	hint := renderNavigatorObservedTargets(got)
	if !strings.Contains(hint, "ordered by expected semantic/response-shape novelty") {
		t.Fatalf("novelty contract missing from prompt hint: %q", hint)
	}
}

func TestReconNoveltyActionSelectsExactCoreBusinessSurface(t *testing.T) {
	nav := NewNavigatorAgent(nil, nil, nil, nil, NewSharedState("https://letterboxd.test/"), nil, 0, nil, policy.AuthorityRecon, nil)
	state := &browser.PageState{
		URL: "https://letterboxd.test/",
		Links: []browser.LinkInfo{
			{Text: "API beta", Href: "/api-beta/"},
			{Text: "Account settings", Href: "/settings/"},
			{Text: "Popular reviews", Href: "/reviews/popular/this/week/"},
			{Text: "A film", Href: "/film/sneakers/"},
		},
	}
	nav.observeNavigationTargets(state)
	action := nav.reconNoveltyAction(nav.navigationDecisionState(state))
	if action == nil {
		t.Fatal("expected deterministic core-business Recon action")
	}
	if action.URL != "https://letterboxd.test/reviews/popular/this/week/" {
		t.Fatalf("novelty action = %+v, want exact review link", action)
	}
	if !strings.Contains(action.Reason, "under-sampled review surface") {
		t.Fatalf("novelty explanation = %q", action.Reason)
	}
}

func TestReconNoveltyActionDefersAfterTwoResponseShapes(t *testing.T) {
	nav := NewNavigatorAgent(nil, nil, nil, nil, NewSharedState("https://app.test/"), nil, 0, nil, policy.AuthorityRecon, nil)
	nav.rememberNavigatorSurface("https://app.test/reviews/", "Reviews", "list-shape")
	nav.rememberNavigatorSurface("https://app.test/reviews/featured/", "Featured reviews", "detail-shape")
	state := &browser.PageState{URL: "https://app.test/", Links: []browser.LinkInfo{{Text: "More reviews", Href: "/reviews/latest/"}}}
	nav.observeNavigationTargets(state)
	if action := nav.reconNoveltyAction(nav.navigationDecisionState(state)); action != nil {
		t.Fatalf("sampled response-shape family should defer to objective-aware planner: %+v", action)
	}
}

func TestReconNoveltyActionNeverSelectsInfrastructureOrSecurityChrome(t *testing.T) {
	nav := NewNavigatorAgent(nil, nil, nil, nil, NewSharedState("https://app.test/"), nil, 0, nil, policy.AuthorityRecon, nil)
	state := &browser.PageState{URL: "https://app.test/", Links: []browser.LinkInfo{
		{Text: "Challenge help", Href: "/cdn-cgi/challenge-platform/help"},
		{Text: "API", Href: "/api/"},
		{Text: "Settings", Href: "/settings/"},
		{Text: "Login", Href: "/login/"},
	}}
	nav.observeNavigationTargets(state)
	if action := nav.reconNoveltyAction(nav.navigationDecisionState(state)); action != nil {
		t.Fatalf("deterministic core reflex selected security/infrastructure chrome: %+v", action)
	}
}

func TestReconLearningObjectivePromotesObservedAuthSurface(t *testing.T) {
	nav := NewNavigatorAgent(nil, nil, nil, nil, NewSharedState("https://app.test/"), nil, 0, nil, policy.AuthorityRecon, nil)
	nav.SetReconObjectives([]ReconObjective{{
		ID: "actor-model", Kind: "privilege", Priority: 9,
		Question: "Which observed identity boundary separates anonymous and signed-in actors?",
	}})
	state := &browser.PageState{URL: "https://app.test/", Links: []browser.LinkInfo{
		{Text: "Popular reviews", Href: "/reviews/popular/"},
		{Text: "Sign in", Href: "/login/"},
	}}
	nav.observeNavigationTargets(state)
	action := nav.reconNoveltyAction(nav.navigationDecisionState(state))
	if action == nil || action.URL != "https://app.test/login/" {
		t.Fatalf("learning objective action = %+v, want exact observed login route", action)
	}
	if !strings.Contains(action.Reason, "Learning loop promoted") || !strings.Contains(action.Reason, "P9 privilege objective") {
		t.Fatalf("learning explanation = %q", action.Reason)
	}
}

func TestNavigatorRecognizesProtectionInterstitialWithoutTreatingTargetPageAsBlocked(t *testing.T) {
	for _, state := range []*browser.PageState{
		{URL: "https://app.test/reviews/", Title: "Just a moment...", VisibleText: "Performing security verification"},
		{URL: "https://app.test/reviews/", Links: []browser.LinkInfo{{Text: "Help", Href: "/cdn-cgi/challenge-platform/help"}}},
	} {
		if !navigatorStateLooksLikeProtectionInterstitial(state) {
			t.Fatalf("protection interstitial was not recognized: %+v", state)
		}
	}
	normal := &browser.PageState{URL: "https://app.test/reviews/", Title: "Popular reviews", VisibleText: "Reviews from members", Links: []browser.LinkInfo{{Text: "Lists", Href: "/lists/"}}}
	if navigatorStateLooksLikeProtectionInterstitial(normal) {
		t.Fatalf("normal target page was mistaken for an interstitial: %+v", normal)
	}
}

func TestNavigatorSemanticStateShapeOmitsTextAndValues(t *testing.T) {
	state := &browser.PageState{
		URL:         "https://app.test/reviews/",
		Title:       "Sensitive title",
		VisibleText: "private target content",
		Forms: []browser.FormInfo{{Method: "POST", Inputs: []browser.InputInfo{
			{Type: "email", Value: "person@example.test"},
			{Type: "hidden", Value: "secret-csrf-token"},
		}}},
		Links:   []browser.LinkInfo{{Text: "Member lists", Href: "/lists/"}},
		Buttons: []browser.ButtonInfo{{Text: "Submit review", Type: "submit", Selector: "#secret-selector"}},
	}
	shape := navigatorSemanticStateShape(state)
	for _, secret := range []string{"private target content", "Sensitive title", "person@example.test", "secret-csrf-token", "secret-selector"} {
		if strings.Contains(shape, secret) {
			t.Fatalf("semantic response shape leaked %q: %s", secret, shape)
		}
	}
	if !strings.Contains(shape, "form:POST:email,hidden") || !strings.Contains(shape, "link:collection") {
		t.Fatalf("semantic response shape lost useful structure: %s", shape)
	}
}

func TestNavigatorDecisionStateCompactsAndRedactsFormInputs(t *testing.T) {
	engine, err := policy.New(policy.AuthorityRecon, []string{"https://target.test"})
	if err != nil {
		t.Fatal(err)
	}
	nav := NewNavigatorAgent(nil, nil, nil, nil, NewSharedState("https://target.test/"), nil, 0, nil, policy.AuthorityRecon, nil)
	nav.SetExecutionPolicy(engine, nil)
	inputs := []browser.InputInfo{{Name: "search", Type: "search", Value: "operator query"}, {Name: "submit", Type: "submit"}}
	for i := 0; i < 18; i++ {
		inputs = append(inputs, browser.InputInfo{Name: "hidden_state", Type: "hidden", Value: "opaque-secret"})
	}
	state := &browser.PageState{URL: "https://target.test/", Forms: []browser.FormInfo{{Action: "/", Method: "POST", Inputs: inputs}}}
	filtered := nav.navigationDecisionState(state)
	if len(filtered.Forms) != 1 || len(filtered.Forms[0].Inputs) != 8 {
		t.Fatalf("compact forms=%+v", filtered.Forms)
	}
	if filtered.Forms[0].Inputs[0].Type != "search" || filtered.Forms[0].Inputs[1].Type != "submit" {
		t.Fatalf("useful controls were not prioritized: %+v", filtered.Forms[0].Inputs)
	}
	for _, input := range filtered.Forms[0].Inputs {
		if input.Value != "" {
			t.Fatalf("input value leaked into decision state: %+v", input)
		}
	}
	if state.Forms[0].Inputs[0].Value != "operator query" || len(state.Forms[0].Inputs) != 20 {
		t.Fatalf("decision projection mutated captured evidence: %+v", state.Forms[0].Inputs)
	}
}

func TestNavigatorDecisionStateCompactsWithoutExplicitPolicy(t *testing.T) {
	nav := NewNavigatorAgent(nil, nil, nil, nil, NewSharedState("https://target.test/"), nil, 0, nil, policy.AuthorityRecon, nil)
	inputs := make([]browser.InputInfo, 0, 20)
	for i := 0; i < 20; i++ {
		inputs = append(inputs, browser.InputInfo{Name: "ambient", Type: "hidden", Value: "never-prompt-this"})
	}
	state := &browser.PageState{
		URL:    "https://target.test/",
		Forms:  []browser.FormInfo{{Action: "/", Method: "POST", Inputs: inputs}},
		Inputs: inputs,
	}

	filtered := nav.navigationDecisionState(state)
	if len(filtered.Forms) != 1 || len(filtered.Forms[0].Inputs) != 8 || len(filtered.Inputs) != 12 {
		t.Fatalf("unbounded decision projection: forms=%d form inputs=%d standalone inputs=%d", len(filtered.Forms), len(filtered.Forms[0].Inputs), len(filtered.Inputs))
	}
	for _, input := range append(filtered.Forms[0].Inputs, filtered.Inputs...) {
		if input.Value != "" {
			t.Fatalf("ambient input value leaked without explicit policy: %+v", input)
		}
	}
}

func TestNavigatorObservedSnapshotOmitsVisitedRoutes(t *testing.T) {
	nav := NewNavigatorAgent(nil, nil, nil, nil, NewSharedState("https://target.test/"), nil, 0, nil, policy.AuthorityRecon, nil)
	nav.observeNavigationTargets(&browser.PageState{
		URL: "https://target.test/",
		Links: []browser.LinkInfo{
			{Text: "Newest", Href: "/newest"},
			{Text: "Jobs", Href: "/jobs"},
		},
	})
	nav.rememberNavigationTarget("/newest", "https://target.test/")

	hint := renderNavigatorObservedTargets(nav.observedNavigationSnapshot(8))
	if strings.Contains(hint, "/newest") {
		t.Fatalf("observed-target hint retained explored route: %q", hint)
	}
	if !strings.Contains(hint, "https://target.test/jobs") || !strings.Contains(hint, "still unexplored") {
		t.Fatalf("observed-target hint lost unexplored exact route: %q", hint)
	}
}

func TestRepeatedNavigatorActionAllowsMateriallyDifferentAttempt(t *testing.T) {
	tests := []struct {
		name   string
		first  *browser.NavigatorAction
		second *browser.NavigatorAction
		url1   string
		url2   string
	}{
		{
			name:   "different page",
			first:  &browser.NavigatorAction{Action: "click", Selector: "#account"},
			second: &browser.NavigatorAction{Action: "click", Selector: "#account"},
			url1:   "http://target.test/",
			url2:   "http://target.test/profile",
		},
		{
			name:   "different input value",
			first:  &browser.NavigatorAction{Action: "fill", Selector: "#search", Value: "alpha"},
			second: &browser.NavigatorAction{Action: "fill", Selector: "#search", Value: "beta"},
			url1:   "http://target.test/search",
			url2:   "http://target.test/search",
		},
		{
			name:   "different destination",
			first:  &browser.NavigatorAction{Action: "navigate", URL: "http://target.test/admin"},
			second: &browser.NavigatorAction{Action: "navigate", URL: "http://target.test/settings"},
			url1:   "http://target.test/",
			url2:   "http://target.test/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seen := make(map[string]struct{})
			if repeatedNavigatorAction(seen, tt.first, tt.url1) {
				t.Fatal("first action was reported as repeated")
			}
			if repeatedNavigatorAction(seen, tt.second, tt.url2) {
				t.Fatal("materially different action was reported as repeated")
			}
		})
	}
}

func TestRepeatedNavigatorActionCanonicalizesNavigateTargets(t *testing.T) {
	seen := make(map[string]struct{})
	first := &browser.NavigatorAction{Action: "navigate", URL: "/api"}
	same := &browser.NavigatorAction{Action: "navigate", URL: "http://target.test/api#ignored"}
	different := &browser.NavigatorAction{Action: "navigate", URL: "/admin"}

	if repeatedNavigatorAction(seen, first, "http://target.test/") {
		t.Fatal("first navigation was reported as repeated")
	}
	if !repeatedNavigatorAction(seen, same, "http://target.test/") {
		t.Fatal("same navigation target with different spelling was not rejected")
	}
	if repeatedNavigatorAction(seen, different, "http://target.test/") {
		t.Fatal("different navigation target was rejected as repeated")
	}
	if got := navigatorActionRepeatTarget(different, "http://target.test/"); got != "http://target.test/admin" {
		t.Fatalf("repeat target = %q, want canonical /admin URL", got)
	}
}

func TestCanonicalNavigatorURLPreservesHashRouterRoutes(t *testing.T) {
	base := "http://target.test/#/search"
	tests := []struct {
		raw  string
		want string
	}{
		{raw: "#/basket", want: "http://target.test/#/basket"},
		{raw: "http://target.test/#!/admin", want: "http://target.test/#!/admin"},
		{raw: "http://target.test/account#section", want: "http://target.test/account"},
	}
	for _, tt := range tests {
		if got := canonicalNavigatorURL(tt.raw, base); got != tt.want {
			t.Fatalf("canonicalNavigatorURL(%q)=%q, want %q", tt.raw, got, tt.want)
		}
	}
}

func TestRepeatedNavigatorActionTreatsHashRoutesAsDifferentPages(t *testing.T) {
	seen := make(map[string]struct{})
	current := "http://target.test/#/"
	search := &browser.NavigatorAction{Action: "navigate", URL: "#/search"}
	searchAgain := &browser.NavigatorAction{Action: "navigate", URL: "http://target.test/#/search"}
	basket := &browser.NavigatorAction{Action: "navigate", URL: "#/basket"}

	if repeatedNavigatorAction(seen, search, current) {
		t.Fatal("first hash-route navigation was reported as repeated")
	}
	if !repeatedNavigatorAction(seen, searchAgain, current) {
		t.Fatal("same hash-route navigation was not treated as repeated")
	}
	if repeatedNavigatorAction(seen, basket, current) {
		t.Fatal("different hash-route navigation was rejected as repeated")
	}
}

func TestValidateNavigatorActionRequiresObservedSelector(t *testing.T) {
	state := &browser.PageState{
		Buttons: []browser.ButtonInfo{{Text: "Account", Selector: "#navbarAccount"}},
		Inputs:  []browser.InputInfo{{Name: "search", Selector: "#searchQuery"}},
	}

	if err := validateNavigatorAction(&browser.NavigatorAction{Action: "click", Selector: "#navbarAccount"}, state); err != nil {
		t.Fatalf("observed selector rejected: %v", err)
	}
	if err := validateNavigatorAction(&browser.NavigatorAction{Action: "fill", Selector: "#searchQuery"}, state); err != nil {
		t.Fatalf("observed input selector rejected: %v", err)
	}
	if err := validateNavigatorAction(&browser.NavigatorAction{Action: "click", Selector: "button:nth-of-type(99)"}, state); err == nil {
		t.Fatal("invented selector was accepted")
	}
}

func TestValidateNavigatorActionRejectsSensitiveBusinessButtons(t *testing.T) {
	state := &browser.PageState{
		Buttons: []browser.ButtonInfo{
			{Text: "Pay now", Selector: "#pay", Type: "submit"},
			{Text: "Confirm booking", Selector: "#book", Type: "submit"},
			{Text: "Delete account", Selector: "#delete", Type: "button"},
			{Text: "Open menu", Selector: "#menu", Type: "button"},
		},
	}

	for _, selector := range []string{"#pay", "#book", "#delete"} {
		t.Run(selector, func(t *testing.T) {
			err := validateNavigatorAction(&browser.NavigatorAction{Action: "click", Selector: selector}, state)
			if err == nil || !strings.Contains(err.Error(), "do not activate") {
				t.Fatalf("sensitive selector %q was not rejected with policy reason: %v", selector, err)
			}
		})
	}
	if err := validateNavigatorAction(&browser.NavigatorAction{Action: "click", Selector: "#menu"}, state); err != nil {
		t.Fatalf("page chrome action should remain allowed: %v", err)
	}
}

func TestValidateNavigatorActionRejectsDestructiveNavigation(t *testing.T) {
	for _, rawURL := range []string{
		"https://example.test/account/logout",
		"https://example.test/delete-account",
		"https://example.test/checkout/confirm",
	} {
		if err := validateNavigatorAction(&browser.NavigatorAction{Action: "navigate", URL: rawURL}, nil); err == nil {
			t.Fatalf("sensitive navigation accepted: %s", rawURL)
		}
	}
	if err := validateNavigatorAction(&browser.NavigatorAction{Action: "navigate", URL: "https://example.test/account"}, nil); err != nil {
		t.Fatalf("read-only account navigation rejected: %v", err)
	}
}

func TestNormalizeNavigatorNavigationURLResolvesObservedRelativeHashRoute(t *testing.T) {
	state := &browser.PageState{
		URL:   "https://shop.example/#/score-board",
		Links: []browser.LinkInfo{{Text: "Complaint", Href: "/#/complain"}},
	}
	action := &browser.NavigatorAction{Action: "navigate", URL: "/#/complain"}

	before, after, changed := normalizeNavigatorNavigationURL(action, state)

	if !changed || before != "/#/complain" || after != "https://shop.example/#/complain" {
		t.Fatalf("relative hash route = before %q after %q changed=%v", before, after, changed)
	}
	if action.URL != after {
		t.Fatalf("action URL = %q, want %q", action.URL, after)
	}
}

func TestNormalizeNavigatorActionForHashRoutingRewritesPlainUIRoutes(t *testing.T) {
	state := &browser.PageState{
		URL: "http://target.test/#/search",
		Links: []browser.LinkInfo{
			{Text: "Account", Href: "http://target.test/#/account"},
		},
	}
	action := &browser.NavigatorAction{Action: "navigate", URL: "/administration"}

	before, after, changed := normalizeNavigatorActionForHashRouting(action, state)

	if !changed {
		t.Fatal("expected plain SPA route to be normalized")
	}
	if before != "/administration" {
		t.Fatalf("before = %q", before)
	}
	if after != "http://target.test/#/administration" || action.URL != after {
		t.Fatalf("normalized route = %q action=%q, want hash route", after, action.URL)
	}
}

func TestNormalizeNavigatorActionForHashRoutingPreservesServerRoutes(t *testing.T) {
	state := &browser.PageState{
		URL: "http://target.test/#/",
		Links: []browser.LinkInfo{
			{Text: "Real server page", Href: "/about"},
		},
	}
	tests := []string{
		"/api/Products",
		"/rest/user/login",
		"/ftp/acquisitions.md",
		"/assets/main.js",
		"/openapi.",
		"/swagger.",
		"/about",
	}
	for _, raw := range tests {
		t.Run(raw, func(t *testing.T) {
			action := &browser.NavigatorAction{Action: "navigate", URL: raw}
			if _, _, changed := normalizeNavigatorActionForHashRouting(action, state); changed {
				t.Fatalf("%s should remain a server/API/static path, got %q", raw, action.URL)
			}
		})
	}
}

func TestNormalizeNavigatorActionForHashRoutingCarriesQueryIntoFragment(t *testing.T) {
	state := &browser.PageState{URL: "https://shop.example/#/"}
	action := &browser.NavigatorAction{Action: "navigate", URL: "/search?q=apple"}

	_, after, changed := normalizeNavigatorActionForHashRouting(action, state)

	if !changed || after != "https://shop.example/#/search?q=apple" {
		t.Fatalf("normalized query route = %q changed=%v", after, changed)
	}
}

func TestNormalizeNavigatorActionForHashRoutingPreservesShellPath(t *testing.T) {
	state := &browser.PageState{URL: "https://shop.example/app/#/home"}
	action := &browser.NavigatorAction{Action: "navigate", URL: "/admin"}

	_, after, changed := normalizeNavigatorActionForHashRouting(action, state)

	if !changed || after != "https://shop.example/app/#/admin" {
		t.Fatalf("normalized mounted-app route = %q changed=%v", after, changed)
	}
}

func TestNavigatorMadeProgress(t *testing.T) {
	before := &browser.PageState{URL: "http://target.test/", VisibleText: "Home"}
	unchanged := &browser.PageState{URL: before.URL, VisibleText: before.VisibleText}
	changed := &browser.PageState{URL: "http://target.test/account", VisibleText: "Account"}

	if navigatorMadeProgress(before, unchanged) {
		t.Fatal("unchanged page was treated as progress")
	}
	if !navigatorMadeProgress(before, changed) {
		t.Fatal("URL and content change was not treated as progress")
	}
}

func TestNavigatorAffordanceHintsEncourageFormInteraction(t *testing.T) {
	state := &browser.PageState{
		Inputs: []browser.InputInfo{
			{Name: "q", Type: "search", Selector: "#searchQuery"},
			{Name: "csrf", Type: "hidden", Selector: "#csrf"},
		},
		Forms: []browser.FormInfo{{
			Inputs: []browser.InputInfo{
				{Name: "email", Type: "email", Selector: "#email"},
				{Name: "password", Type: "password", Selector: "#password"},
			},
		}},
		Buttons: []browser.ButtonInfo{{Text: "Login", Selector: "#loginButton"}},
	}

	hints := navigatorAffordanceHints(state)
	for _, want := range []string{
		"Visible fillable inputs exist",
		"#searchQuery(search)",
		"#email(email)",
		"#password(password)",
		"aobtd-nav@example.test",
		"Login",
	} {
		if !strings.Contains(hints, want) {
			t.Fatalf("navigatorAffordanceHints() missing %q in:\n%s", want, hints)
		}
	}
	if strings.Contains(hints, "#csrf") {
		t.Fatalf("hidden input should not be suggested as fillable:\n%s", hints)
	}
}

func TestNavigatorAffordanceHintsExplainGuardedBusinessControls(t *testing.T) {
	state := &browser.PageState{
		Buttons: []browser.ButtonInfo{
			{Text: "Confirm booking", Selector: "#book", Type: "submit"},
			{Text: "Pay now", Selector: "#pay", Type: "submit"},
		},
	}

	hints := navigatorAffordanceHints(state)
	for _, want := range []string{
		"Sensitive business controls visible",
		"Confirm booking(sensitive_state_change)",
		"Pay now(financial)",
	} {
		if !strings.Contains(hints, want) {
			t.Fatalf("navigatorAffordanceHints() missing %q in:\n%s", want, hints)
		}
	}
}

func TestNavigatorAffordanceHintsWarnOnHashRoutedSPA(t *testing.T) {
	state := &browser.PageState{
		URL: "http://target.test/#/",
		Links: []browser.LinkInfo{
			{Text: "Admin", Href: "http://target.test/#/administration"},
			{Text: "Account", Href: "http://target.test/#/account"},
		},
	}

	hints := navigatorAffordanceHints(state)
	for _, want := range []string{
		"Hash-routed SPA detected",
		"avoid guessing plain app paths",
		"#/administration",
		"#/account",
	} {
		if !strings.Contains(hints, want) {
			t.Fatalf("navigatorAffordanceHints() missing %q in:\n%s", want, hints)
		}
	}
}

func TestNextSafeFormActionFillsThenSubmits(t *testing.T) {
	state := &browser.PageState{
		URL: "http://target.test/#/login",
		Forms: []browser.FormInfo{{
			Inputs: []browser.InputInfo{
				{Name: "email", Type: "email", Selector: "#email"},
				{Name: "password", Type: "password", Selector: "#password"},
			},
		}},
		Buttons: []browser.ButtonInfo{{Text: "Log in", Selector: "#loginButton", Type: "submit"}},
	}
	memory := make(map[string]*navigatorFormMemory)

	first := nextSafeFormAction(state, memory)
	if first == nil || first.Action != "fill" || first.Selector != "#email" || first.Value != "aobtd-nav@example.test" {
		t.Fatalf("first action = %#v, want email fill", first)
	}
	second := nextSafeFormAction(state, memory)
	if second == nil || second.Action != "fill" || second.Selector != "#password" || second.Value != "Password1!" {
		t.Fatalf("second action = %#v, want password fill", second)
	}
	third := nextSafeFormAction(state, memory)
	if third == nil || third.Action != "click" || third.Selector != "#loginButton" {
		t.Fatalf("third action = %#v, want login click", third)
	}
	if fourth := nextSafeFormAction(state, memory); fourth != nil {
		t.Fatalf("expected no further action after submit, got %#v", fourth)
	}
}

func TestNextSafeFormActionAvoidsDestructiveSubmit(t *testing.T) {
	state := &browser.PageState{
		URL:    "http://target.test/#/checkout",
		Inputs: []browser.InputInfo{{Name: "amount", Type: "number", Selector: "#amount"}},
		Buttons: []browser.ButtonInfo{
			{Text: "Pay now", Selector: "#pay", Type: "submit"},
			{Text: "Delete account", Selector: "#delete", Type: "button"},
		},
	}
	memory := make(map[string]*navigatorFormMemory)

	first := nextSafeFormAction(state, memory)
	if first == nil || first.Action != "fill" || first.Selector != "#amount" {
		t.Fatalf("first action = %#v, want safe numeric fill", first)
	}
	if second := nextSafeFormAction(state, memory); second != nil {
		t.Fatalf("destructive submit should be avoided, got %#v", second)
	}
}

func TestNavigatorSafeSubmitButtonPrefersWorkflowOverChrome(t *testing.T) {
	button, ok := navigatorSafeSubmitButton([]browser.ButtonInfo{
		{Text: "close", Selector: `button[aria-label="Close search"]`, Type: "button"},
		{Text: "Account", Selector: "#navbarAccount", Type: "button"},
		{Text: "Log in", Selector: "#loginButton", Type: "submit"},
	}, []browser.InputInfo{{Name: "password", Type: "password", Selector: "#password"}})
	if !ok {
		t.Fatal("expected a safe submit button")
	}
	if button.Selector != "#loginButton" {
		t.Fatalf("selected %q, want #loginButton", button.Selector)
	}
}

func TestNavigatorSafeSubmitButtonRejectsChromeSearchButton(t *testing.T) {
	if button, ok := navigatorSafeSubmitButton([]browser.ButtonInfo{
		{Text: "search", Selector: `button[aria-label="Open search"]`, Type: "button"},
		{Text: "Account", Selector: "#navbarAccount", Type: "button"},
	}, []browser.InputInfo{{Name: "q", Type: "search", Selector: "#search"}}); ok {
		t.Fatalf("chrome button was selected as form submit: %#v", button)
	}
}

func TestNavigatorSearchInputNeverChoosesUnrelatedLogin(t *testing.T) {
	button, ok := navigatorSafeSubmitButton([]browser.ButtonInfo{
		{Text: "Giriş Yap", Selector: "#loginButton", Type: "button"},
		{Text: "Ara", Selector: "#searchSubmit", Type: "submit"},
	}, []browser.InputInfo{{Name: "Search", Type: "search", Selector: "#search"}})
	if !ok {
		t.Fatal("expected the search workflow to find its submit control")
	}
	if button.Selector != "#searchSubmit" {
		t.Fatalf("search workflow selected %q, want #searchSubmit", button.Selector)
	}
}

func TestNavigatorSearchInputDoesNotSubmitLoginWhenSearchButtonIsMissing(t *testing.T) {
	if button, ok := navigatorSafeSubmitButton([]browser.ButtonInfo{
		{Text: "Giriş Yap", Selector: "#loginButton", Type: "button"},
	}, []browser.InputInfo{{Name: "Search", Type: "search", Selector: "#search"}}); ok {
		t.Fatalf("search workflow selected unrelated auth control: %#v", button)
	}
}

func TestNavigatorControlRiskClassifiesBusinessControls(t *testing.T) {
	tests := []struct {
		text string
		want workflow.ControlRisk
	}{
		{"Log in", workflow.ControlSafe},
		{"Search products", workflow.ControlSafe},
		{"Open search", workflow.ControlChrome},
		{"Close search", workflow.ControlChrome},
		{"Show the shopping cart", workflow.ControlChrome},
		{"Pay now", workflow.ControlFinancial},
		{"Transfer balance", workflow.ControlFinancial},
		{"Place order", workflow.ControlSensitiveStateChange},
		{"Confirm booking", workflow.ControlSensitiveStateChange},
		{"Siparişi Onayla", workflow.ControlSensitiveStateChange},
		{"Ödeme yap", workflow.ControlFinancial},
		{"Kupon kullan", workflow.ControlSensitiveStateChange},
		{"Delete account", workflow.ControlDestructive},
		{"Reset password", workflow.ControlDestructive},
	}
	for _, tt := range tests {
		t.Run(tt.text, func(t *testing.T) {
			if got := workflow.ClassifyControl(tt.text); got != tt.want {
				t.Fatalf("workflow.ClassifyControl(%q)=%q, want %q", tt.text, got, tt.want)
			}
		})
	}
}

func TestNavigatorSafeSubmitButtonRejectsSensitiveBusinessActions(t *testing.T) {
	if button, ok := navigatorSafeSubmitButton([]browser.ButtonInfo{
		{Text: "Pay now", Selector: "#pay", Type: "submit"},
		{Text: "Place order", Selector: "#order", Type: "submit"},
		{Text: "Kupon kullan", Selector: "#coupon", Type: "submit"},
		{Text: "Confirm booking", Selector: "#book", Type: "submit"},
		{Text: "Transfer balance", Selector: "#transfer", Type: "submit"},
	}, []browser.InputInfo{{Name: "amount", Type: "number", Selector: "#amount"}}); ok {
		t.Fatalf("risky business action button was selected: %#v", button)
	}
}

func TestRedactNavigatorActionValue(t *testing.T) {
	got := redactNavigatorActionValue(&browser.NavigatorAction{
		Action:   "fill",
		Selector: "#password",
		Value:    "Password1!",
	})
	if got != "<redacted-password>" {
		t.Fatalf("password value was not redacted: %q", got)
	}

	got = redactNavigatorActionValue(&browser.NavigatorAction{
		Action:   "fill",
		Selector: "#email",
		Value:    "aobtd-nav@example.test",
	})
	if got != "aobtd-nav@example.test" {
		t.Fatalf("non-secret value was unexpectedly changed: %q", got)
	}
}
