package extract

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

// HTMLExtraction holds all security-relevant elements extracted from an HTML page.
type HTMLExtraction struct {
	Forms            []ExtractedForm  `json:"forms,omitempty"`
	StandaloneInputs []ExtractedInput `json:"standalone_inputs,omitempty"`
	Links            []ExtractedLink  `json:"links,omitempty"`
	HiddenFields     []ExtractedInput `json:"hidden_fields,omitempty"`
	MetaTags         []MetaTag        `json:"meta_tags,omitempty"`
	Comments         []string         `json:"comments,omitempty"`
	Title            string           `json:"title,omitempty"`
	// Headings and preformatted-block count are bounded structural routing
	// hints. They help distinguish an opaque documentation filename from a
	// news or marketing page before an LLM call; they are never promoted as
	// application claims on their own.
	Headings           []string `json:"headings,omitempty"`
	PreformattedBlocks int      `json:"preformatted_blocks,omitempty"`
}

// ExtractedForm represents an HTML form with its inputs.
type ExtractedForm struct {
	Action  string           `json:"action,omitempty"`
	Method  string           `json:"method,omitempty"`
	Enctype string           `json:"enctype,omitempty"`
	ID      string           `json:"id,omitempty"`
	Inputs  []ExtractedInput `json:"inputs"`
}

// ExtractedInput represents an input, select, or textarea element.
type ExtractedInput struct {
	Tag         string   `json:"tag"`
	Name        string   `json:"name,omitempty"`
	Type        string   `json:"type,omitempty"`
	Value       string   `json:"value,omitempty"`
	Placeholder string   `json:"placeholder,omitempty"`
	Label       string   `json:"label,omitempty"`
	Pattern     string   `json:"pattern,omitempty"`
	AcceptTypes string   `json:"accept,omitempty"`
	Required    bool     `json:"required,omitempty"`
	MinLength   int      `json:"min_length,omitempty"`
	MaxLength   int      `json:"max_length,omitempty"`
	Options     []string `json:"options,omitempty"`
}

// ExtractedLink represents an anchor element.
type ExtractedLink struct {
	Href       string `json:"href"`
	Text       string `json:"text,omitempty"`
	IsAPI      bool   `json:"is_api,omitempty"`
	SameOrigin bool   `json:"same_origin,omitempty"`
}

// MetaTag represents a meta element.
type MetaTag struct {
	Name    string `json:"name"`
	Content string `json:"content"`
}

// ExtractHTML parses raw HTML and extracts security-relevant structure.
// pageURL is used to resolve relative URLs and determine same-origin links.
func ExtractHTML(rawHTML []byte, pageURL string) *HTMLExtraction {
	doc, err := html.Parse(strings.NewReader(string(rawHTML)))
	if err != nil {
		return &HTMLExtraction{}
	}

	ext := &HTMLExtraction{}
	pageHost := ""
	if parsed, err := url.Parse(pageURL); err == nil {
		pageHost = strings.ToLower(parsed.Hostname())
	}

	// Collect all label elements for matching by "for" attribute
	labels := collectLabels(doc)

	// Walk the tree
	var walk func(*html.Node, *ExtractedForm)
	walk = func(n *html.Node, currentForm *ExtractedForm) {
		switch n.Type {
		case html.CommentNode:
			comment := strings.TrimSpace(n.Data)
			if comment != "" && len(comment) < 500 {
				ext.Comments = append(ext.Comments, comment)
			}

		case html.ElementNode:
			switch n.DataAtom {
			case atom.Title:
				ext.Title = boundedSemanticText(textContent(n), 180)

			case atom.H1, atom.H2, atom.H3:
				if len(ext.Headings) < 12 {
					heading := boundedSemanticText(textContent(n), 180)
					if heading != "" && !containsStringFold(ext.Headings, heading) {
						ext.Headings = append(ext.Headings, heading)
					}
				}

			case atom.Pre:
				if ext.PreformattedBlocks < 32 {
					ext.PreformattedBlocks++
				}

			case atom.Form:
				form := extractForm(n, pageURL)
				// Walk children within this form context
				for c := n.FirstChild; c != nil; c = c.NextSibling {
					walk(c, &form)
				}
				ext.Forms = append(ext.Forms, form)
				return // already walked children

			case atom.Input, atom.Textarea, atom.Select:
				inp := extractInput(n, labels)
				if currentForm != nil {
					currentForm.Inputs = append(currentForm.Inputs, inp)
				} else {
					// Input outside any form
					if inp.Type == "hidden" {
						ext.HiddenFields = append(ext.HiddenFields, inp)
					} else {
						ext.StandaloneInputs = append(ext.StandaloneInputs, inp)
					}
				}

			case atom.A:
				link := extractLink(n, pageURL, pageHost)
				if link.Href != "" {
					ext.Links = append(ext.Links, link)
				}

			case atom.Meta:
				meta := extractMeta(n)
				if meta.Name != "" && meta.Content != "" {
					ext.MetaTags = append(ext.MetaTags, meta)
				}
			}
		}

		// Walk children (unless already handled by form)
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c, currentForm)
		}
	}

	walk(doc, nil)

	// Separate hidden fields from form inputs
	for i := range ext.Forms {
		var visible []ExtractedInput
		for _, inp := range ext.Forms[i].Inputs {
			if inp.Type == "hidden" {
				ext.HiddenFields = append(ext.HiddenFields, inp)
			}
			visible = append(visible, inp)
		}
		ext.Forms[i].Inputs = visible
	}

	// Deduplicate links
	ext.Links = deduplicateLinks(ext.Links)

	return ext
}

func boundedSemanticText(value string, limit int) string {
	value = strings.Join(strings.Fields(value), " ")
	if limit <= 0 || len(value) <= limit {
		return value
	}
	return strings.TrimSpace(value[:limit])
}

func containsStringFold(values []string, candidate string) bool {
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), strings.TrimSpace(candidate)) {
			return true
		}
	}
	return false
}

// InputSignature returns a stable hash-like string representing the input structure.
// Used for template matching — pages with the same input signature are likely the same template.
func (e *HTMLExtraction) InputSignature() string {
	var parts []string
	for _, f := range e.Forms {
		formSig := fmt.Sprintf("form:%s:%s", f.Method, f.Action)
		for _, inp := range f.Inputs {
			formSig += fmt.Sprintf("|%s:%s:%s", inp.Tag, inp.Name, inp.Type)
		}
		parts = append(parts, formSig)
	}
	for _, inp := range e.StandaloneInputs {
		parts = append(parts, fmt.Sprintf("standalone:%s:%s:%s", inp.Tag, inp.Name, inp.Type))
	}
	// Sort for stability
	sortStrings(parts)
	return strings.Join(parts, ";")
}

// TotalInputCount returns the total number of input elements found.
func (e *HTMLExtraction) TotalInputCount() int {
	count := len(e.StandaloneInputs) + len(e.HiddenFields)
	for _, f := range e.Forms {
		count += len(f.Inputs)
	}
	return count
}

func extractForm(n *html.Node, pageURL string) ExtractedForm {
	f := ExtractedForm{
		Method: "GET", // default
	}
	for _, attr := range n.Attr {
		switch strings.ToLower(attr.Key) {
		case "action":
			f.Action = resolveURL(attr.Val, pageURL)
		case "method":
			f.Method = strings.ToUpper(attr.Val)
		case "enctype":
			f.Enctype = attr.Val
		case "id":
			f.ID = attr.Val
		}
	}
	return f
}

func extractInput(n *html.Node, labels map[string]string) ExtractedInput {
	inp := ExtractedInput{
		Tag: n.Data,
	}

	for _, attr := range n.Attr {
		switch strings.ToLower(attr.Key) {
		case "name":
			inp.Name = attr.Val
		case "type":
			inp.Type = strings.ToLower(attr.Val)
		case "value":
			if len(attr.Val) <= 100 {
				inp.Value = attr.Val
			}
		case "placeholder":
			inp.Placeholder = attr.Val
		case "required":
			inp.Required = true
		case "pattern":
			inp.Pattern = attr.Val
		case "accept":
			inp.AcceptTypes = attr.Val
		case "minlength":
			inp.MinLength, _ = strconv.Atoi(attr.Val)
		case "maxlength":
			inp.MaxLength, _ = strconv.Atoi(attr.Val)
		case "id":
			// Check for matching label
			if lbl, ok := labels[attr.Val]; ok {
				inp.Label = lbl
			}
		}
	}

	// Default type for input
	if inp.Tag == "input" && inp.Type == "" {
		inp.Type = "text"
	}
	if inp.Tag == "textarea" {
		inp.Type = "textarea"
	}

	// Extract select options
	if n.DataAtom == atom.Select {
		inp.Type = "select"
		inp.Options = extractOptions(n)
	}

	// Try to find label from parent or preceding sibling if not found by "for"
	if inp.Label == "" {
		inp.Label = findNearbyLabel(n)
	}

	return inp
}

func extractLink(n *html.Node, pageURL, pageHost string) ExtractedLink {
	link := ExtractedLink{
		Text: strings.TrimSpace(textContent(n)),
	}

	for _, attr := range n.Attr {
		if strings.ToLower(attr.Key) == "href" {
			link.Href = attr.Val
			break
		}
	}

	if link.Href == "" || strings.HasPrefix(link.Href, "javascript:") ||
		strings.HasPrefix(link.Href, "#") || strings.HasPrefix(link.Href, "mailto:") ||
		strings.HasPrefix(link.Href, "tel:") {
		return ExtractedLink{}
	}

	// Resolve relative URL
	resolved := resolveURL(link.Href, pageURL)
	if resolved != "" {
		link.Href = resolved
	}

	// Check same-origin
	if parsed, err := url.Parse(link.Href); err == nil {
		linkHost := strings.ToLower(parsed.Hostname())
		if linkHost == pageHost || linkHost == "" {
			link.SameOrigin = true
		}
	}

	// Check if API path
	lower := strings.ToLower(link.Href)
	if strings.Contains(lower, "/api/") || strings.Contains(lower, "/graphql") ||
		strings.Contains(lower, "/rest/") || strings.Contains(lower, "/v1/") ||
		strings.Contains(lower, "/v2/") || strings.Contains(lower, "/v3/") {
		link.IsAPI = true
	}

	// Truncate link text
	if len(link.Text) > 80 {
		link.Text = link.Text[:80]
	}

	return link
}

func extractMeta(n *html.Node) MetaTag {
	var meta MetaTag
	for _, attr := range n.Attr {
		switch strings.ToLower(attr.Key) {
		case "name", "property", "http-equiv":
			meta.Name = attr.Val
		case "content":
			if len(attr.Val) <= 200 {
				meta.Content = attr.Val
			}
		}
	}
	return meta
}

func extractOptions(n *html.Node) []string {
	var opts []string
	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if node.DataAtom == atom.Option {
			val := getAttr(node, "value")
			if val == "" {
				val = strings.TrimSpace(textContent(node))
			}
			if val != "" && len(opts) < 20 { // cap at 20 options
				opts = append(opts, val)
			}
		}
		for c := node.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
	return opts
}

// collectLabels maps id -> label text for all <label for="id"> elements.
func collectLabels(doc *html.Node) map[string]string {
	labels := make(map[string]string)
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.DataAtom == atom.Label {
			forAttr := getAttr(n, "for")
			if forAttr != "" {
				labels[forAttr] = strings.TrimSpace(textContent(n))
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return labels
}

// findNearbyLabel tries to find label text from parent label or preceding text node.
func findNearbyLabel(n *html.Node) string {
	// Check if parent is a <label>
	if n.Parent != nil && n.Parent.DataAtom == atom.Label {
		// Get text content excluding the input itself
		var text string
		for c := n.Parent.FirstChild; c != nil; c = c.NextSibling {
			if c != n && c.Type == html.TextNode {
				text += c.Data
			}
		}
		text = strings.TrimSpace(text)
		if text != "" {
			return text
		}
	}

	// Check preceding sibling text node
	if n.PrevSibling != nil && n.PrevSibling.Type == html.TextNode {
		text := strings.TrimSpace(n.PrevSibling.Data)
		if text != "" && len(text) < 100 {
			return text
		}
	}

	return ""
}

func textContent(n *html.Node) string {
	if n.Type == html.TextNode {
		return n.Data
	}
	var sb strings.Builder
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		sb.WriteString(textContent(c))
	}
	return sb.String()
}

func getAttr(n *html.Node, key string) string {
	for _, attr := range n.Attr {
		if strings.EqualFold(attr.Key, key) {
			return attr.Val
		}
	}
	return ""
}

func resolveURL(href, baseURL string) string {
	if strings.HasPrefix(href, "http://") || strings.HasPrefix(href, "https://") {
		return href
	}
	base, err := url.Parse(baseURL)
	if err != nil {
		return href
	}
	ref, err := url.Parse(href)
	if err != nil {
		return href
	}
	return base.ResolveReference(ref).String()
}

func deduplicateLinks(links []ExtractedLink) []ExtractedLink {
	seen := make(map[string]bool)
	var result []ExtractedLink
	for _, l := range links {
		if !seen[l.Href] {
			seen[l.Href] = true
			result = append(result, l)
		}
	}
	return result
}

func sortStrings(ss []string) {
	// Simple insertion sort — these slices are small
	for i := 1; i < len(ss); i++ {
		for j := i; j > 0 && ss[j] < ss[j-1]; j-- {
			ss[j], ss[j-1] = ss[j-1], ss[j]
		}
	}
}
