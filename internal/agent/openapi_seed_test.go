package agent

import "testing"

func TestOpenAPISafeGETTargets(t *testing.T) {
	spec := []byte(`{
	  "openapi": "3.0.0",
	  "servers": [{"url": ""}],
	  "paths": {
	    "/": {"get": {"summary": "home"}},
	    "/books/v1": {"get": {"summary": "List books"}, "post": {"summary": "Add book"}},
	    "/books/v1/{book_title}": {"get": {"summary": "Get book by title"}},
	    "/createdb": {"get": {"summary": "Creates and populates the database"}},
	    "/users/v1": {"get": {"summary": "List users"}},
	    "/users/v1/_debug": {"get": {"summary": "Debug dump"}},
	    "/users/v1/login": {"post": {"summary": "Login"}},
	    "/users/v1/register": {"post": {"summary": "Register"}}
	  }
	}`)

	got := openAPISafeGETTargets(spec, "http://127.0.0.1:5002/openapi.json", 20)
	var urls []string
	for _, target := range got {
		urls = append(urls, target.URL)
	}
	want := []string{
		"http://127.0.0.1:5002/",
		"http://127.0.0.1:5002/books/v1",
		"http://127.0.0.1:5002/users/v1",
		"http://127.0.0.1:5002/users/v1/_debug",
	}
	if len(urls) != len(want) {
		t.Fatalf("urls = %#v, want %#v", urls, want)
	}
	for i := range want {
		if urls[i] != want[i] {
			t.Fatalf("urls[%d] = %q, want %q (all=%#v)", i, urls[i], want[i], urls)
		}
	}
}

func TestOpenAPISafeGETTargetsRejectsNonSpec(t *testing.T) {
	got := openAPISafeGETTargets([]byte(`{"paths":{"/users":{"get":{}}}}`), "https://example.test/openapi.json", 20)
	if len(got) != 0 {
		t.Fatalf("non-spec targets = %#v", got)
	}
}

func TestResolveOpenAPIPathRequiresConcretePath(t *testing.T) {
	if got := resolveOpenAPIPath("https://example.test/", "/users/{id}"); got != "" {
		t.Fatalf("path param target = %q, want empty", got)
	}
	if got := resolveOpenAPIPath("https://example.test/api/", "/users"); got != "https://example.test/users" {
		t.Fatalf("resolved = %q", got)
	}
}
