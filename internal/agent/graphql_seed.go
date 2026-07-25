package agent

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/ozzyw/aobtd/internal/extract"
	"github.com/ozzyw/aobtd/internal/store"
)

const graphQLIntrospectionQuery = `{__schema{queryType{name} mutationType{name} types{name kind fields{name type{name kind ofType{name kind}}}}}}`

func (a *AnalyzerAgent) enqueueGraphQLFollowUps(bundle *extract.EndpointBundle) {
	if a == nil || a.db == nil || bundle == nil {
		return
	}
	endpointURL := graphQLEndpointURL(bundle.SampleURL)
	if endpointURL == "" {
		endpointURL = graphQLEndpointURL(bundle.URLPattern)
	}
	if endpointURL == "" {
		return
	}
	sourceProfileID := fmt.Sprintf("%s %s", bundle.Method, bundle.URLPattern)
	id, err := a.db.InsertFollowUp(a.scanID, store.FollowUp{
		SourceAgent:     "analyzer",
		SourceProfileID: sourceProfileID,
		Action:          "graphql_introspect",
		URL:             endpointURL,
		Reason:          "GraphQL endpoint observed; perform safe POST schema introspection to map query and mutation surface.",
		Priority:        9,
	})
	if err != nil {
		a.logger.Warn("graphql introspection follow-up queue failed", "url", endpointURL, "error", err)
		return
	}
	if id > 0 {
		a.db.InsertNarration(a.scanID, "analyzer", "graphql_seed",
			fmt.Sprintf("Queued GraphQL schema introspection for %s.", endpointURL),
			endpointURL, map[string]any{"source_profile_id": sourceProfileID})
	}
}

func graphQLEndpointURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	path := strings.Trim(strings.ToLower(parsed.Path), "/")
	if path == "" {
		return ""
	}
	parts := strings.Split(path, "/")
	if parts[len(parts)-1] != "graphql" {
		return ""
	}
	if parsed.Path != "/" {
		parsed.Path = strings.TrimRight(parsed.Path, "/")
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}
