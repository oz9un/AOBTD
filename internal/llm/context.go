package llm

import (
	"fmt"
	"strings"

	"github.com/ozzyw/aobtd/internal/extract"
	"github.com/ozzyw/aobtd/pkg/types"
)

// ContextPacker builds LLM prompts from traffic and knowledge base data.
type ContextPacker struct {
	maxTokens int
}

// NewContextPacker creates a context packer targeting the given token limit.
func NewContextPacker(maxTokens int) *ContextPacker {
	if maxTokens == 0 {
		maxTokens = 12000
	}
	return &ContextPacker{maxTokens: maxTokens}
}

// BuildBundleContext renders an EndpointBundle into a compact text representation for LLM consumption.
func BuildBundleContext(bundle *extract.EndpointBundle) string {
	if bundle == nil {
		return ""
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "## Endpoint: %s %s\n", bundle.Method, bundle.URLPattern)
	fmt.Fprintf(&sb, "Sample URL: %s\n", bundle.SampleURL)
	fmt.Fprintf(&sb, "Traffic entries: %d\n", bundle.EntryCount)

	if len(bundle.StatusCodes) > 0 {
		fmt.Fprintf(&sb, "Status codes: %v\n", bundle.StatusCodes)
	}

	// Auth info
	if auth, ok := bundle.RequestHeaders["authorization"]; ok {
		fmt.Fprintf(&sb, "Auth: %s\n", auth)
	} else if _, ok := bundle.RequestHeaders["cookie"]; ok {
		sb.WriteString("Auth: session cookie\n")
	} else {
		sb.WriteString("Auth: none observed\n")
	}

	// Request params
	if len(bundle.QueryParams) > 0 {
		sb.WriteString("\n### Query Parameters\n")
		for _, p := range bundle.QueryParams {
			required := ""
			if p.Required {
				required = " (required)"
			}
			fmt.Fprintf(&sb, "  - %s (%s)%s", p.Name, p.Type, required)
			if len(p.Examples) > 0 {
				fmt.Fprintf(&sb, " examples: %s", strings.Join(p.Examples, ", "))
			}
			sb.WriteString("\n")
		}
	}

	if len(bundle.BodyParams) > 0 {
		sb.WriteString("\n### Body Parameters\n")
		for _, p := range bundle.BodyParams {
			required := ""
			if p.Required {
				required = " (required)"
			}
			fmt.Fprintf(&sb, "  - %s (%s, in %s)%s", p.Name, p.Type, p.Location, required)
			if len(p.Examples) > 0 {
				fmt.Fprintf(&sb, " examples: %s", strings.Join(p.Examples, ", "))
			}
			sb.WriteString("\n")
		}
	}

	// HTML extraction
	if bundle.HTMLExtraction != nil {
		ext := bundle.HTMLExtraction
		if ext.Title != "" {
			fmt.Fprintf(&sb, "\n### Page: %s\n", ext.Title)
		}

		for _, form := range ext.Forms {
			fmt.Fprintf(&sb, "\n### Form: %s %s", form.Method, form.Action)
			if form.Enctype != "" {
				fmt.Fprintf(&sb, " (%s)", form.Enctype)
			}
			sb.WriteString("\n")

			for _, inp := range form.Inputs {
				flags := ""
				if inp.Required {
					flags += " (required)"
				}
				if inp.Label != "" {
					flags += fmt.Sprintf(" label: %q", inp.Label)
				}
				if inp.Placeholder != "" {
					flags += fmt.Sprintf(" placeholder: %q", inp.Placeholder)
				}
				if inp.Pattern != "" {
					flags += fmt.Sprintf(" pattern: %s", inp.Pattern)
				}
				if inp.AcceptTypes != "" {
					flags += fmt.Sprintf(" accept: %s", inp.AcceptTypes)
				}
				if inp.MaxLength > 0 {
					flags += fmt.Sprintf(" maxlength: %d", inp.MaxLength)
				}
				if len(inp.Options) > 0 {
					opts := inp.Options
					if len(opts) > 5 {
						opts = append(opts[:5], fmt.Sprintf("...(%d more)", len(inp.Options)-5))
					}
					flags += fmt.Sprintf(" options: [%s]", strings.Join(opts, ", "))
				}
				fmt.Fprintf(&sb, "    - %s: %s (type: %s)%s\n", inp.Tag, inp.Name, inp.Type, flags)
			}
		}

		if len(ext.StandaloneInputs) > 0 {
			sb.WriteString("\n### Standalone Inputs (outside forms)\n")
			for _, inp := range ext.StandaloneInputs {
				fmt.Fprintf(&sb, "    - %s: %s (type: %s)\n", inp.Tag, inp.Name, inp.Type)
			}
		}

		if len(ext.HiddenFields) > 0 {
			sb.WriteString("\n### Hidden Fields\n")
			for _, inp := range ext.HiddenFields {
				val := inp.Value
				if len(val) > 40 {
					val = val[:40] + "..."
				}
				fmt.Fprintf(&sb, "    - %s = %q\n", inp.Name, val)
			}
		}

		if len(ext.Comments) > 0 {
			sb.WriteString("\n### HTML Comments\n")
			for _, c := range ext.Comments {
				if len(c) > 200 {
					c = c[:200] + "..."
				}
				fmt.Fprintf(&sb, "    <!-- %s -->\n", c)
			}
		}

		// Same-origin links (limit to 20)
		var sameOrigin []extract.ExtractedLink
		for _, l := range ext.Links {
			if l.SameOrigin && len(sameOrigin) < 20 {
				sameOrigin = append(sameOrigin, l)
			}
		}
		if len(sameOrigin) > 0 {
			sb.WriteString("\n### Links (same-origin)\n")
			for _, l := range sameOrigin {
				api := ""
				if l.IsAPI {
					api = " [API]"
				}
				fmt.Fprintf(&sb, "    - %s%s\n", l.Href, api)
			}
		}
	}

	// JSON schema
	if bundle.JSONSchema != nil {
		sb.WriteString("\n### Response JSON Schema\n")
		sb.WriteString(extract.RenderSchema(bundle.JSONSchema))
		sb.WriteString("\n")
	}

	// Security-relevant response headers
	if len(bundle.ResponseHeaders) > 0 {
		sb.WriteString("\n### Response Headers\n")
		for k, v := range bundle.ResponseHeaders {
			fmt.Fprintf(&sb, "    %s: %s\n", k, v)
		}
	}

	return sb.String()
}

// BuildAppUnderstandingContext renders the app understanding for LLM injection.
// Delegates to AppUnderstanding.RenderForLLM().
func BuildAppUnderstandingContext(u *extract.AppUnderstanding) string {
	if u == nil {
		return ""
	}
	return u.RenderForLLM()
}

// BuildEndpointIndex creates a one-line-per-endpoint summary for context.
func BuildEndpointIndex(endpoints []types.Endpoint) string {
	if len(endpoints) == 0 {
		return "No endpoints discovered yet."
	}

	var sb strings.Builder
	sb.WriteString("## Known Endpoints\n")

	for _, ep := range endpoints {
		flags := ""
		if len(ep.Parameters) > 0 {
			flags += " [params]"
		}
		if ep.AuthNeeded {
			flags += " [auth]"
		}
		if ep.Purpose != "" {
			flags += " - " + ep.Purpose
		}
		fmt.Fprintf(&sb, "- %s %s%s\n", ep.Method, ep.URLPattern, flags)
	}

	return sb.String()
}

// BuildProfileContext creates context from a PageProfile for injection.
func BuildProfileContext(profile *types.PageProfile) string {
	if profile == nil {
		return ""
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "## Existing Knowledge: %s %s\n", profile.Method, profile.URL)
	if profile.Purpose != "" {
		fmt.Fprintf(&sb, "Purpose: %s\n", profile.Purpose)
	}
	if profile.AuthRequired != "" && profile.AuthRequired != "unknown" {
		fmt.Fprintf(&sb, "Auth: %s\n", profile.AuthRequired)
	}
	if len(profile.Inputs) > 0 {
		sb.WriteString("Inputs: ")
		for i, inp := range profile.Inputs {
			if i > 0 {
				sb.WriteString(", ")
			}
			fmt.Fprintf(&sb, "%s(%s)", inp.Name, inp.Type)
		}
		sb.WriteString("\n")
	}
	if len(profile.Issues) > 0 {
		sb.WriteString("Known Issues:\n")
		for _, issue := range profile.Issues {
			fmt.Fprintf(&sb, "  - %s\n", issue)
		}
	}
	if len(profile.Behaviors) > 0 {
		sb.WriteString("Behaviors:\n")
		for _, b := range profile.Behaviors {
			fmt.Fprintf(&sb, "  - %s\n", b)
		}
	}

	return sb.String()
}

