package llm

import (
	"context"
	"errors"
	"testing"
)

type fallbackTestProvider struct {
	model    string
	response *Response
	err      error
	calls    int
}

func (p *fallbackTestProvider) Complete(context.Context, *Request) (*Response, error) {
	p.calls++
	return p.response, p.err
}
func (p *fallbackTestProvider) CountTokens(s string) int { return len(s) }
func (p *fallbackTestProvider) ModelInfo() ModelInfo {
	return ModelInfo{Name: p.model, SupportsJSON: true}
}
func (p *fallbackTestProvider) Name() string { return p.model }

func TestFallbackProviderRetriesErrors(t *testing.T) {
	primary := &fallbackTestProvider{model: "deep", err: errors.New("timeout")}
	fallback := &fallbackTestProvider{model: "scout", response: &Response{Content: `{"ok":true}`}}
	p := NewFallbackProvider(primary, fallback, nil)

	resp, err := p.Complete(context.Background(), &Request{JSONMode: true})
	if err != nil || resp.Content != `{"ok":true}` {
		t.Fatalf("Complete() = %#v, %v", resp, err)
	}
	if primary.calls != 1 || fallback.calls != 1 {
		t.Fatalf("calls primary=%d fallback=%d", primary.calls, fallback.calls)
	}
	if resp.Model != "scout" {
		t.Fatalf("response model=%q, want scout", resp.Model)
	}
}

func TestFallbackProviderRetriesMalformedJSON(t *testing.T) {
	primary := &fallbackTestProvider{model: "deep", response: &Response{Content: "thinking aloud"}}
	fallback := &fallbackTestProvider{model: "scout", response: &Response{Content: "```json\n{\"ok\":true}\n```"}}
	p := NewFallbackProvider(primary, fallback, nil)

	if _, err := p.Complete(context.Background(), &Request{JSONMode: true}); err != nil {
		t.Fatal(err)
	}
	if fallback.calls != 1 {
		t.Fatalf("fallback calls=%d, want 1", fallback.calls)
	}
}

func TestFallbackProviderKeepsPrimaryForText(t *testing.T) {
	primary := &fallbackTestProvider{model: "deep", response: &Response{Content: "free form"}}
	fallback := &fallbackTestProvider{model: "scout", response: &Response{Content: "unused"}}
	p := NewFallbackProvider(primary, fallback, nil)

	if _, err := p.Complete(context.Background(), &Request{}); err != nil {
		t.Fatal(err)
	}
	if fallback.calls != 0 {
		t.Fatalf("fallback calls=%d, want 0", fallback.calls)
	}
}
