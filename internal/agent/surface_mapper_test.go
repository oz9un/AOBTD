package agent

import (
	"strings"
	"testing"
)

func TestSurfaceValuesDecodeAndPreserveRepeatedParameters(t *testing.T) {
	values := parseSurfaceValues("q=hello+world&id=41&id=42")
	if len(values) != 3 {
		t.Fatalf("values = %+v", values)
	}
	if values[0].name != "id" || values[0].value != "41" || values[2].value != "hello world" {
		t.Fatalf("decoded values = %+v", values)
	}
}

func TestSurfaceMapperIgnoresStaticCacheVersionButKeepsApplicationQuery(t *testing.T) {
	if !ignoreSurfaceQueryParam("/assets/app.js", "v", "v=abc123") {
		t.Fatal("static version token should not become an attack-surface input")
	}
	if ignoreSurfaceQueryParam("/api/search", "v", "v=abc123") {
		t.Fatal("same parameter on application endpoint should remain input")
	}
	if ignoreSurfaceQueryParam("/assets/image.svg", "theme", "theme=dark") {
		t.Fatal("non-cache query on a static-backed dynamic resource should remain visible")
	}
}

func TestSurfaceMapperDeprioritizesTelemetryEnvelopeInputs(t *testing.T) {
	for _, tc := range []struct {
		path string
		name string
	}{
		{"/awe/api/v2/rum", "long_task.scripts[].source_url"},
		{"/ces/v1/t", "context.page.url"},
		{"/cdn-cgi/challenge-platform/h/g/jsd/oneshot", "view.url"},
	} {
		if !ignoreSurfaceBodyParam(tc.path, tc.name) {
			t.Fatalf("telemetry input %s %s should be deprioritized", tc.path, tc.name)
		}
	}
	if ignoreSurfaceBodyParam("/api/fetch-preview", "url") {
		t.Fatal("application URL input must remain visible")
	}
}

func TestFlattenSurfaceJSONFindsNestedIdentifiers(t *testing.T) {
	value := map[string]any{
		"order": map[string]any{
			"customer": map[string]any{"id": "42"},
			"items":    []any{map[string]any{"productId": "7", "quantity": "2"}},
		},
	}
	flattened := flattenSurfaceJSON(value, "", 0, 20)
	joined := make([]string, 0, len(flattened))
	for _, item := range flattened {
		joined = append(joined, item.name+"="+item.value)
	}
	got := strings.Join(joined, ",")
	for _, want := range []string{"order.customer.id=42", "order.items[].productId=7", "order.items[].quantity=2"} {
		if !strings.Contains(got, want) {
			t.Fatalf("nested JSON missing %q: %s", want, got)
		}
	}
}

func TestInferSurfaceAuthType(t *testing.T) {
	if got := inferSurfaceAuthType(`{"Authorization":"Bearer token"}`, true); got != "bearer" {
		t.Fatalf("bearer auth = %q", got)
	}
	if got := inferSurfaceAuthType(`{"Cookie":"session=abc"}`, true); got != "cookie" {
		t.Fatalf("cookie auth = %q", got)
	}
	if got := inferSurfaceAuthType(`{}`, false); got != "none" {
		t.Fatalf("no auth = %q", got)
	}
}
