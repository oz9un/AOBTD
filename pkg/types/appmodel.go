package types

// Endpoint represents a discovered API endpoint or page.
type Endpoint struct {
	ID         string      `json:"id"`
	Method     string      `json:"method"`
	URLPattern string      `json:"url_pattern"`
	Parameters []Parameter `json:"parameters,omitempty"`
	AuthNeeded bool        `json:"auth_needed"`
	Purpose    string      `json:"purpose,omitempty"`
	HitCount   int         `json:"hit_count"`
}

// Parameter represents an input to an endpoint.
type Parameter struct {
	Name     string `json:"name"`
	Location string `json:"location"` // query, body, header, path, cookie
	Type     string `json:"type"`     // string, int, uuid, email, etc.
	Example  string `json:"example,omitempty"`
}

// AuthFlow represents a discovered authentication mechanism.
type AuthFlow struct {
	Type      string `json:"type"`       // session_cookie, bearer_token, basic, api_key
	LoginURL  string `json:"login_url"`
	TokenName string `json:"token_name"` // cookie name or header name
}

// TechStack holds detected technology information.
type TechStack struct {
	Server      string   `json:"server,omitempty"`
	Framework   string   `json:"framework,omitempty"`
	Language    string   `json:"language,omitempty"`
	CDN         string   `json:"cdn,omitempty"`
	WAF         string   `json:"waf,omitempty"`
	JSLibraries []string `json:"js_libraries,omitempty"`
}

// AppModel is the aggregate application model built during a scan.
type AppModel struct {
	Target    string     `json:"target"`
	Endpoints []Endpoint `json:"endpoints"`
	AuthFlows []AuthFlow `json:"auth_flows,omitempty"`
	TechStack TechStack  `json:"tech_stack"`
	Findings  []Finding  `json:"findings,omitempty"`
}
