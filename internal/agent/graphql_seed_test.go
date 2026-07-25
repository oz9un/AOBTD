package agent

import "testing"

func TestGraphQLEndpointURLStripsQueryAndRejectsNonGraphQL(t *testing.T) {
	if got := graphQLEndpointURL("https://example.test/graphql?query={__schema{types{name}}}#frag"); got != "https://example.test/graphql" {
		t.Fatalf("graphql endpoint = %q", got)
	}
	if got := graphQLEndpointURL("https://example.test/api/users"); got != "" {
		t.Fatalf("non-graphql endpoint = %q, want empty", got)
	}
	if got := graphQLEndpointURL("https://example.test/static/jquery/graphql.js"); got != "" {
		t.Fatalf("graphql-named static asset = %q, want empty", got)
	}
	if got := graphQLEndpointURL("https://example.test/api/graphql/"); got != "https://example.test/api/graphql" {
		t.Fatalf("nested graphql endpoint = %q", got)
	}
}

func TestGraphQLIntrospectionLogicProbe(t *testing.T) {
	if !graphQLIntrospectionLogicProbe("https://example.test/graphql", "query", []logicProbe{
		{StatusCode: 200, BodyBytes: []byte(`{"data":{"__schema":{"types":[{"name":"Query"}]}}}`)},
	}) {
		t.Fatal("expected GraphQL introspection response to be recognized")
	}
	if graphQLIntrospectionLogicProbe("https://example.test/static/jquery/graphql.js", "query", []logicProbe{
		{StatusCode: 200, BodyBytes: []byte(`{"data":{"__schema":{"types":[{"name":"Query"}]}}}`)},
	}) {
		t.Fatal("static graphql.js must not be treated as a GraphQL endpoint")
	}
	if graphQLIntrospectionLogicProbe("https://example.test/graphql", "search", []logicProbe{
		{StatusCode: 200, BodyBytes: []byte(`{"data":{"__schema":{"types":[{"name":"Query"}]}}}`)},
	}) {
		t.Fatal("non-query field must not be treated as introspection")
	}
}

func TestBuildPlaceholderHTTPRequestUsesConcreteHost(t *testing.T) {
	got := buildPlaceholderHTTPRequest("POST", "https://example.test/graphql?debug=1", "<body>")
	if got != "POST /graphql?debug=1 HTTP/1.1\nHost: example.test\n\n<body>" {
		t.Fatalf("request = %q", got)
	}
}
