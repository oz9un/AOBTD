package proxy

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/ozzyw/aobtd/internal/policy"
	"github.com/ozzyw/aobtd/pkg/types"
)

func TestPassiveRenderDependencyRequiresEverySecurityInvariant(t *testing.T) {
	const (
		pageURL  = "https://app.example.test/dashboard"
		assetURL = "https://cdn.vendor.test/runtime.js?v=7"
	)
	engine, err := policy.New(policy.AuthorityRecon, []string{"https://app.example.test"})
	if err != nil {
		t.Fatal(err)
	}

	newRequest := func(method, target, destination, referer string, body io.Reader) *http.Request {
		req, reqErr := http.NewRequest(method, target, body)
		if reqErr != nil {
			t.Fatal(reqErr)
		}
		if destination != "" {
			req.Header.Set("Sec-Fetch-Dest", destination)
		}
		if referer != "" {
			req.Header.Set("Referer", referer)
		}
		return req
	}
	decisionFor := func(req *http.Request) policy.Decision {
		return engine.AuthorizeHTTPRequest(req, "https://app.example.test")
	}

	for _, destination := range []string{"font", "image", "script", "style", "SCRIPT"} {
		req := newRequest(http.MethodGet, assetURL, destination, pageURL, nil)
		decision := decisionFor(req)
		if decision.Code != policy.CodeOutOfScope || !allowPassiveRenderDependency(req, decision, engine) {
			t.Errorf("valid %q dependency rejected: %+v", destination, decision)
		}
	}
	for _, unsafeTarget := range []string{
		"http://127.0.0.1/pixel.png",
		"http://[::1]/runtime.js",
		"http://169.254.169.254/latest/meta-data/iam",
		"http://10.0.0.8/theme.css",
		"http://metadata.google.internal/computeMetadata/v1/",
		"http://service.internal/app.js",
		"file:///etc/passwd",
	} {
		req := newRequest(http.MethodGet, unsafeTarget, "script", pageURL, nil)
		if allowPassiveRenderDependency(req, decisionFor(req), engine) {
			t.Errorf("internal/private target received passive-render exception: %s", unsafeTarget)
		}
	}
	head := newRequest(http.MethodHead, assetURL, "image", pageURL, nil)
	if !allowPassiveRenderDependency(head, decisionFor(head), engine) {
		t.Fatal("credential-free passive HEAD dependency was rejected")
	}

	tests := []struct {
		name   string
		build  func() *http.Request
		mutate func(*http.Request)
		code   policy.DecisionCode
	}{
		{name: "only out-of-scope denial qualifies", build: func() *http.Request {
			return newRequest(http.MethodGet, pageURL, "script", pageURL, nil)
		}, code: policy.CodeAllowed},
		{name: "post", build: func() *http.Request {
			return newRequest(http.MethodPost, assetURL, "script", pageURL, nil)
		}, code: policy.CodeOutOfScope},
		{name: "get body", build: func() *http.Request {
			return newRequest(http.MethodGet, assetURL, "script", pageURL, bytes.NewBufferString("payload"))
		}, code: policy.CodeOutOfScope},
		{name: "missing destination", build: func() *http.Request {
			return newRequest(http.MethodGet, assetURL, "", pageURL, nil)
		}, code: policy.CodeOutOfScope},
		{name: "document navigation", build: func() *http.Request {
			return newRequest(http.MethodGet, assetURL, "document", pageURL, nil)
		}, code: policy.CodeOutOfScope},
		{name: "xhr or fetch", build: func() *http.Request {
			req := newRequest(http.MethodGet, assetURL, "unused", pageURL, nil)
			req.Header.Set("Sec-Fetch-Dest", "empty")
			return req
		}, code: policy.CodeOutOfScope},
		{name: "manifest", build: func() *http.Request {
			return newRequest(http.MethodGet, assetURL, "manifest", pageURL, nil)
		}, code: policy.CodeOutOfScope},
		{name: "worker", build: func() *http.Request {
			return newRequest(http.MethodGet, assetURL, "worker", pageURL, nil)
		}, code: policy.CodeOutOfScope},
		{name: "missing referer", build: func() *http.Request {
			return newRequest(http.MethodGet, assetURL, "script", "", nil)
		}, code: policy.CodeOutOfScope},
		{name: "off-scope referer", build: func() *http.Request {
			return newRequest(http.MethodGet, assetURL, "script", "https://other.example.test/page", nil)
		}, code: policy.CodeOutOfScope},
		{name: "referer fragment", build: func() *http.Request {
			return newRequest(http.MethodGet, assetURL, "script", pageURL+"#secret", nil)
		}, code: policy.CodeOutOfScope},
		{name: "target bearer query", build: func() *http.Request {
			return newRequest(http.MethodGet, assetURL+"&access_token=secret", "script", pageURL, nil)
		}, code: policy.CodeOutOfScope},
		{name: "signed target", build: func() *http.Request {
			return newRequest(http.MethodGet, assetURL+"&X-Amz-Signature=secret", "script", pageURL, nil)
		}, code: policy.CodeOutOfScope},
		{name: "generic key query", build: func() *http.Request {
			return newRequest(http.MethodGet, assetURL+"&key=secret", "script", pageURL, nil)
		}, code: policy.CodeOutOfScope},
		{name: "generic secret query", build: func() *http.Request {
			return newRequest(http.MethodGet, assetURL+"&secret=value", "script", pageURL, nil)
		}, code: policy.CodeOutOfScope},
		{name: "generic password query", build: func() *http.Request {
			return newRequest(http.MethodGet, assetURL+"&password=value", "script", pageURL, nil)
		}, code: policy.CodeOutOfScope},
		{name: "custom token query", build: func() *http.Request {
			return newRequest(http.MethodGet, assetURL+"&vendor_token=value", "script", pageURL, nil)
		}, code: policy.CodeOutOfScope},
		{name: "client secret query", build: func() *http.Request {
			return newRequest(http.MethodGet, assetURL+"&client_secret=value", "script", pageURL, nil)
		}, code: policy.CodeOutOfScope},
		{name: "tokenized referer", build: func() *http.Request {
			return newRequest(http.MethodGet, assetURL, "script", pageURL+"?session_id=secret", nil)
		}, code: policy.CodeOutOfScope},
		{name: "cookie", build: func() *http.Request {
			req := newRequest(http.MethodGet, assetURL, "script", pageURL, nil)
			req.Header.Set("Cookie", "session=secret")
			return req
		}, code: policy.CodeOutOfScope},
		{name: "authorization", build: func() *http.Request {
			req := newRequest(http.MethodGet, assetURL, "script", pageURL, nil)
			req.Header.Set("Authorization", "Bearer secret")
			return req
		}, code: policy.CodeOutOfScope},
		{name: "csrf token", build: func() *http.Request {
			req := newRequest(http.MethodGet, assetURL, "script", pageURL, nil)
			req.Header.Set("X-CSRF-Token", "secret")
			return req
		}, code: policy.CodeOutOfScope},
		{name: "signature header", build: func() *http.Request {
			req := newRequest(http.MethodGet, assetURL, "script", pageURL, nil)
			req.Header.Set("X-Request-Signature", "secret")
			return req
		}, code: policy.CodeOutOfScope},
		{name: "generic secret header", build: func() *http.Request {
			req := newRequest(http.MethodGet, assetURL, "script", pageURL, nil)
			req.Header.Set("Secret", "value")
			return req
		}, code: policy.CodeOutOfScope},
		{name: "generic API key header", build: func() *http.Request {
			req := newRequest(http.MethodGet, assetURL, "script", pageURL, nil)
			req.Header.Set("Api-Key", "value")
			return req
		}, code: policy.CodeOutOfScope},
		{name: "host override mismatch", build: func() *http.Request {
			req := newRequest(http.MethodGet, assetURL, "script", pageURL, nil)
			req.Host = "attacker.example.test"
			return req
		}, code: policy.CodeHostOverrideMismatch},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := tt.build()
			if tt.mutate != nil {
				tt.mutate(req)
			}
			decision := decisionFor(req)
			if decision.Code != tt.code {
				t.Fatalf("decision code = %s, want %s (%+v)", decision.Code, tt.code, decision)
			}
			if allowPassiveRenderDependency(req, decision, engine) {
				t.Fatal("unsafe request received passive-render exception")
			}
		})
	}

	valid := newRequest(http.MethodGet, assetURL, "script", pageURL, nil)
	fakeDenial := decisionFor(valid)
	fakeDenial.Code = policy.CodeAuthorityDenied
	if allowPassiveRenderDependency(valid, fakeDenial, engine) {
		t.Fatal("a non-out-of-scope denial was bypassed")
	}
}

func TestPassiveRenderRegistryAllowsOnlyExactDestinationBoundAssetsWithoutReferer(t *testing.T) {
	const pageURL = "https://app.example.test/dashboard"
	engine, err := policy.New(policy.AuthorityRecon, []string{"https://app.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	registry := newPassiveRenderAssetRegistry(engine)
	registry.ObserveAuthorizedDocument(&types.TrafficEntry{
		Request: types.CapturedRequest{
			Method:  http.MethodGet,
			URL:     pageURL,
			Headers: map[string]string{"Sec-Fetch-Dest": "document"},
		},
		Response: types.CapturedResponse{
			StatusCode:  http.StatusOK,
			ContentType: "text/html; charset=utf-8",
			Body: []byte(`<!doctype html><html><head>
				<base href="https://cdn.vendor.test/app/">
				<script src="runtime.js?v=7"></script>
				<link rel="stylesheet" href="https://styles.vendor.test/theme.css">
				<link rel="preload" as="font" href="https://fonts.vendor.test/demo.woff2">
				<style>.hero{background:url('https://images.vendor.test/hero.webp')}</style>
			</head><body><img src="https://images.vendor.test/logo.png"></body></html>`),
		},
	})

	decisionFor := func(req *http.Request) policy.Decision {
		return engine.AuthorizeHTTPRequest(req, "https://app.example.test")
	}
	request := func(target, destination string) *http.Request {
		req, reqErr := http.NewRequest(http.MethodGet, target, nil)
		if reqErr != nil {
			t.Fatal(reqErr)
		}
		req.Header.Set("Sec-Fetch-Dest", destination)
		return req
	}
	for _, allowed := range []struct {
		url         string
		destination string
	}{
		{url: "https://cdn.vendor.test/app/runtime.js?v=7", destination: "script"},
		// Chromium's proxy URL may preserve the default CONNECT port even when
		// the HTML declaration omitted it. These are the same exact URL.
		{url: "https://cdn.vendor.test:443/app/runtime.js?v=7", destination: "script"},
		{url: "https://styles.vendor.test/theme.css", destination: "style"},
		{url: "https://fonts.vendor.test/demo.woff2", destination: "font"},
		{url: "https://images.vendor.test/hero.webp", destination: "image"},
		{url: "https://images.vendor.test/logo.png", destination: "image"},
	} {
		req := request(allowed.url, allowed.destination)
		if !allowPassiveRenderDependencyWithRegistry(req, decisionFor(req), engine, registry) {
			t.Errorf("exact no-Referer asset rejected: %s (%s)", allowed.url, allowed.destination)
		}
	}

	for _, denied := range []struct {
		name        string
		url         string
		destination string
	}{
		{name: "query value changed", url: "https://cdn.vendor.test/app/runtime.js?v=8", destination: "script"},
		{name: "query removed", url: "https://cdn.vendor.test/app/runtime.js", destination: "script"},
		{name: "destination changed", url: "https://cdn.vendor.test/app/runtime.js?v=7", destination: "image"},
		{name: "unknown same host", url: "https://cdn.vendor.test/app/other.js?v=7", destination: "script"},
		{name: "non-default port", url: "https://cdn.vendor.test:444/app/runtime.js?v=7", destination: "script"},
		{name: "xhr", url: "https://cdn.vendor.test/app/runtime.js?v=7", destination: "empty"},
		{name: "navigation", url: "https://cdn.vendor.test/app/runtime.js?v=7", destination: "document"},
		{name: "secret query", url: "https://cdn.vendor.test/app/runtime.js?v=7&token=secret", destination: "script"},
	} {
		t.Run(denied.name, func(t *testing.T) {
			req := request(denied.url, denied.destination)
			if allowPassiveRenderDependencyWithRegistry(req, decisionFor(req), engine, registry) {
				t.Fatal("request received registry exception")
			}
		})
	}

	cookie := request("https://cdn.vendor.test/app/runtime.js?v=7", "script")
	cookie.Header.Set("Cookie", "session=secret")
	if allowPassiveRenderDependencyWithRegistry(cookie, decisionFor(cookie), engine, registry) {
		t.Fatal("credential-bearing exact asset received registry exception")
	}
	forgedReferer := request("https://cdn.vendor.test/app/runtime.js?v=7", "script")
	forgedReferer.Header.Set("Referer", "https://attacker.example.test/")
	if allowPassiveRenderDependencyWithRegistry(forgedReferer, decisionFor(forgedReferer), engine, registry) {
		t.Fatal("present but unauthorized Referer fell back to registry")
	}
}

func TestPassiveRenderRegistryDoesNotLearnFromUnverifiedDocumentsOrPrivateTargets(t *testing.T) {
	engine, err := policy.New(policy.AuthorityRecon, []string{"https://app.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	registry := newPassiveRenderAssetRegistry(engine)
	observe := func(documentURL, destination, contentType string, status int, body string) {
		registry.ObserveAuthorizedDocument(&types.TrafficEntry{
			Request: types.CapturedRequest{
				Method: http.MethodGet, URL: documentURL,
				Headers: map[string]string{"Sec-Fetch-Dest": destination},
			},
			Response: types.CapturedResponse{
				StatusCode: status, ContentType: contentType, Body: []byte(body),
			},
		})
	}
	body := `<script src="https://cdn.vendor.test/runtime.js"></script>`
	observe("https://attacker.example.test/page", "document", "text/html", http.StatusOK, body)
	observe("https://app.example.test/api", "empty", "text/html", http.StatusOK, body)
	observe("https://app.example.test/error", "document", "text/html", http.StatusNotFound, body)
	observe("https://app.example.test/blob", "document", "application/json", http.StatusOK, body)
	observe("https://app.example.test/private", "document", "text/html", http.StatusOK,
		`<script src="http://127.0.0.1/admin.js"></script><img src="http://169.254.169.254/meta">`)

	for _, target := range []string{
		"https://cdn.vendor.test/runtime.js",
		"http://127.0.0.1/admin.js",
		"http://169.254.169.254/meta",
	} {
		parsed, parseErr := url.Parse(target)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		if registry.AllowsExact(parsed, "script") || registry.AllowsExact(parsed, "image") {
			t.Errorf("untrusted/private target was registered: %s", target)
		}
	}
}

func TestPassiveRenderRegistryCarriesOnlyExactRedirectSuccessor(t *testing.T) {
	const (
		pageURL  = "https://app.example.test/"
		assetURL = "https://cdn.vendor.test/runtime.js?v=7"
	)
	engine, err := policy.New(policy.AuthorityRecon, []string{"https://app.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	registry := newPassiveRenderAssetRegistry(engine)
	registry.ObserveAuthorizedDocument(&types.TrafficEntry{
		Request:  types.CapturedRequest{Method: http.MethodGet, URL: pageURL, Headers: map[string]string{"Sec-Fetch-Dest": "document"}},
		Response: types.CapturedResponse{StatusCode: http.StatusOK, ContentType: "text/html", Body: []byte(`<script src="` + assetURL + `"></script>`)},
	})
	registry.ObserveAllowedRedirect(&types.CapturedRequest{
		Method: http.MethodGet, URL: assetURL, Headers: map[string]string{"Sec-Fetch-Dest": "script"},
	}, &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": []string{"https://edge.vendor.test/runtime-v2.js?v=7"}}})

	redirected, _ := url.Parse("https://edge.vendor.test/runtime-v2.js?v=7")
	unknown, _ := url.Parse("https://edge.vendor.test/runtime-v3.js?v=7")
	if !registry.AllowsExact(redirected, "script") {
		t.Fatal("exact redirect successor was not registered")
	}
	if registry.AllowsExact(redirected, "image") || registry.AllowsExact(unknown, "script") {
		t.Fatal("redirect grant expanded beyond exact URL/destination")
	}
}

func passiveHTTPTestDialer(handler http.Handler, publicIP net.IP) passiveNetworkDialer {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		if !net.ParseIP(host).Equal(publicIP) {
			return (&net.Dialer{}).DialContext(ctx, network, address)
		}
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			request, readErr := http.ReadRequest(bufio.NewReader(server))
			if readErr != nil {
				return
			}
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			response := recorder.Result()
			defer response.Body.Close()
			response.Request = request
			_ = response.Write(server)
		}()
		return &passiveTestConn{
			Conn:   client,
			remote: &net.TCPAddr{IP: append(net.IP(nil), publicIP...), Port: 8081},
		}, nil
	}
}

func TestProxyAllowsOnlyFilteredPassiveRenderDependencies(t *testing.T) {
	var cdnHits atomic.Int32
	cdnHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cdnHits.Add(1)
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = io.WriteString(w, "window.demoReady = true")
	})
	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<main>demo</main>")
	}))
	defer page.Close()

	engine, err := policy.New(policy.AuthorityRecon, []string{page.URL})
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	var callbackMu sync.Mutex
	var captured []*types.TrafficEntry
	var callbackSawUnfiltered atomic.Bool
	var audits atomic.Int32
	p, err := New("127.0.0.1", 0, filepath.Join(t.TempDir(), "certs"), func(entry *types.TrafficEntry) {
		if !entry.Filtered {
			callbackSawUnfiltered.Store(true)
		}
		callbackMu.Lock()
		captured = append(captured, entry)
		callbackMu.Unlock()
	}, engine, page.URL, func(policy.Decision) {
		audits.Add(1)
	}, logger)
	if err != nil {
		t.Fatal(err)
	}
	const cdnPublicOrigin = "http://cdn.public.example:8081"
	publicIP := net.ParseIP("93.184.216.34")
	p.gp.Tr.DialContext = newPassiveRenderDialContext(staticPassiveResolver{addresses: map[string][]net.IPAddr{
		"cdn.public.example": {{IP: publicIP}},
	}}, passiveHTTPTestDialer(cdnHandler, publicIP))
	proxyServer := httptest.NewServer(p.gp)
	defer proxyServer.Close()
	proxyURL, err := url.Parse(proxyServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	var lastClientBody []byte
	do := func(method, target, destination, referer string, body io.Reader, headers http.Header) int {
		req, reqErr := http.NewRequest(method, target, body)
		if reqErr != nil {
			t.Fatal(reqErr)
		}
		if destination != "" {
			req.Header.Set("Sec-Fetch-Dest", destination)
		}
		if referer != "" {
			req.Header.Set("Referer", referer)
		}
		for key, values := range headers {
			req.Header[key] = append([]string(nil), values...)
		}
		resp, doErr := client.Do(req)
		if doErr != nil {
			t.Fatal(doErr)
		}
		lastClientBody, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode
	}

	if status := do(http.MethodGet, cdnPublicOrigin+"/runtime.js?v=7", "script", page.URL+"/dashboard", nil, nil); status != http.StatusOK {
		t.Fatalf("passive asset status = %d, want 200", status)
	}
	if cdnHits.Load() != 1 {
		t.Fatalf("passive asset upstream hits = %d, want 1", cdnHits.Load())
	}
	if string(lastClientBody) != "window.demoReady = true" {
		t.Fatalf("browser received altered passive body %q", lastClientBody)
	}
	if audits.Load() != 0 {
		t.Fatalf("allowed passive asset produced %d denial audits", audits.Load())
	}
	callbackMu.Lock()
	if len(captured) != 1 || captured[0].Request.URL != cdnPublicOrigin+"/runtime.js?v=7" ||
		!captured[0].Filtered || len(captured[0].Response.Body) != 0 {
		t.Fatalf("captured passive entry = %+v", captured)
	}
	callbackMu.Unlock()
	if callbackSawUnfiltered.Load() {
		t.Fatal("capture callback observed the CDN dependency as target evidence")
	}

	denied := []struct {
		name        string
		method      string
		destination string
		referer     string
		target      string
		body        io.Reader
		headers     http.Header
	}{
		{name: "navigation", method: http.MethodGet, destination: "document", referer: page.URL, target: cdnPublicOrigin + "/page"},
		{name: "xhr-fetch", method: http.MethodGet, destination: "empty", referer: page.URL, target: cdnPublicOrigin + "/api"},
		{name: "manifest", method: http.MethodGet, destination: "manifest", referer: page.URL, target: cdnPublicOrigin + "/app.webmanifest"},
		{name: "mutation", method: http.MethodPost, destination: "script", referer: page.URL, target: cdnPublicOrigin + "/runtime.js", body: bytes.NewBufferString("payload")},
		{name: "cookie", method: http.MethodGet, destination: "image", referer: page.URL, target: cdnPublicOrigin + "/pixel.png", headers: http.Header{"Cookie": []string{"session=secret"}}},
		{name: "no referer", method: http.MethodGet, destination: "style", target: cdnPublicOrigin + "/app.css"},
		{name: "off-scope referer", method: http.MethodGet, destination: "script", referer: cdnPublicOrigin + "/parent", target: cdnPublicOrigin + "/runtime.js"},
		{name: "signed URL", method: http.MethodGet, destination: "image", referer: page.URL, target: cdnPublicOrigin + "/hero.png?X-Amz-Signature=secret"},
	}
	for _, tt := range denied {
		t.Run(tt.name, func(t *testing.T) {
			if status := do(tt.method, tt.target, tt.destination, tt.referer, tt.body, tt.headers); status != http.StatusForbidden {
				t.Fatalf("status = %d, want 403", status)
			}
		})
	}
	if cdnHits.Load() != 1 {
		t.Fatalf("denied requests reached CDN: hits = %d, want 1", cdnHits.Load())
	}
	callbackMu.Lock()
	defer callbackMu.Unlock()
	if len(captured) != 1 {
		t.Fatalf("denied requests entered capture callback: entries = %d", len(captured))
	}
	if audits.Load() != int32(len(denied)) {
		t.Fatalf("denial audits = %d, want %d", audits.Load(), len(denied))
	}
}

func TestProxyLearnsExactAssetFromAuthorizedDocumentWhenRefererIsStripped(t *testing.T) {
	const cdnOrigin = "http://static.public.example:8082"
	var cdnHits atomic.Int32
	cdnHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		cdnHits.Add(1)
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = io.WriteString(w, "window.rendered = true")
	})
	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Referrer-Policy", "same-origin")
		_, _ = io.WriteString(w, `<html><head><script src="`+cdnOrigin+`/runtime.js?v=7"></script></head></html>`)
	}))
	defer page.Close()

	engine, err := policy.New(policy.AuthorityRecon, []string{page.URL})
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	var callbackMu sync.Mutex
	var captured []*types.TrafficEntry
	var audits atomic.Int32
	p, err := New("127.0.0.1", 0, filepath.Join(t.TempDir(), "certs"), func(entry *types.TrafficEntry) {
		callbackMu.Lock()
		captured = append(captured, entry)
		callbackMu.Unlock()
	}, engine, page.URL, func(policy.Decision) { audits.Add(1) }, logger)
	if err != nil {
		t.Fatal(err)
	}
	publicIP := net.ParseIP("93.184.216.34")
	p.gp.Tr.DialContext = newPassiveRenderDialContext(staticPassiveResolver{addresses: map[string][]net.IPAddr{
		"static.public.example": {{IP: publicIP}},
	}}, passiveHTTPTestDialer(cdnHandler, publicIP))
	proxyServer := httptest.NewServer(p.gp)
	defer proxyServer.Close()
	proxyURL, err := url.Parse(proxyServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	do := func(target, destination string, headers http.Header) (int, []byte) {
		req, reqErr := http.NewRequest(http.MethodGet, target, nil)
		if reqErr != nil {
			t.Fatal(reqErr)
		}
		req.Header.Set("Sec-Fetch-Dest", destination)
		for key, values := range headers {
			req.Header[key] = append([]string(nil), values...)
		}
		resp, doErr := client.Do(req)
		if doErr != nil {
			t.Fatal(doErr)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode, body
	}

	if status, _ := do(page.URL+"/dashboard", "document", nil); status != http.StatusOK {
		t.Fatalf("authorized document status = %d", status)
	}
	status, body := do(cdnOrigin+"/runtime.js?v=7", "script", nil)
	if status != http.StatusOK || string(body) != "window.rendered = true" {
		t.Fatalf("exact stripped-Referer asset = status %d body %q", status, body)
	}
	for _, denied := range []struct {
		url         string
		destination string
		headers     http.Header
	}{
		{url: cdnOrigin + "/runtime.js?v=8", destination: "script"},
		{url: cdnOrigin + "/runtime.js?v=7", destination: "empty"},
		{url: cdnOrigin + "/runtime.js?v=7", destination: "document"},
		{url: cdnOrigin + "/runtime.js?v=7", destination: "script", headers: http.Header{"Cookie": []string{"session=secret"}}},
	} {
		if status, _ := do(denied.url, denied.destination, denied.headers); status != http.StatusForbidden {
			t.Errorf("unsafe registry request status = %d, want 403 (%s %s)", status, denied.destination, denied.url)
		}
	}

	if cdnHits.Load() != 1 {
		t.Fatalf("CDN hits = %d, want exactly 1", cdnHits.Load())
	}
	if audits.Load() != 4 {
		t.Fatalf("denial audits = %d, want 4", audits.Load())
	}
	callbackMu.Lock()
	defer callbackMu.Unlock()
	if len(captured) != 2 {
		t.Fatalf("capture entries = %d, want document + exact asset", len(captured))
	}
	if captured[0].Filtered || !captured[1].Filtered || len(captured[1].Response.Body) != 0 {
		t.Fatalf("document/asset filter state = %v/%v, passive body=%d",
			captured[0].Filtered, captured[1].Filtered, len(captured[1].Response.Body))
	}
}
