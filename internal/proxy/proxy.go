package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/elazarl/goproxy"
	"github.com/ozzyw/aobtd/internal/observation"
	"github.com/ozzyw/aobtd/internal/policy"
	"github.com/ozzyw/aobtd/pkg/types"
)

// Proxy is a MITM HTTP/HTTPS proxy that captures traffic.
type Proxy struct {
	server      *http.Server
	gp          *goproxy.ProxyHttpServer
	interceptor *Interceptor
	certStore   *CertStore
	logger      *slog.Logger
	addr        string

	mu      sync.Mutex
	running bool
}

type proxyCapturedContext struct {
	captured      *types.CapturedRequest
	policyAllowed bool
	passiveRender bool
}

// SetTrafficProvenanceResolver wires browser-agent attribution into the
// request capture boundary.
func (p *Proxy) SetTrafficProvenanceResolver(resolver observation.ProvenanceResolver) {
	if p == nil || p.interceptor == nil {
		return
	}
	p.interceptor.SetTrafficProvenanceResolver(resolver)
}

// New creates a new MITM proxy.
func New(listenAddr string, port int, certDir string, callback TrafficCallback,
	executionPolicy *policy.Engine, credentialOrigin string, audit policy.DecisionAudit,
	logger *slog.Logger,
) (*Proxy, error) {
	if executionPolicy == nil {
		return nil, fmt.Errorf("execution policy is required")
	}
	cs, err := NewCertStore(certDir)
	if err != nil {
		return nil, fmt.Errorf("cert store: %w", err)
	}

	interceptor := NewInterceptor(callback, logger)
	passiveAssets := newPassiveRenderAssetRegistry(executionPolicy)
	policyLogCounts := make(map[string]int)
	var policyLogMu sync.Mutex

	gp := goproxy.NewProxyHttpServer()
	installPassiveRenderNetworkGuard(gp.Tr)
	gp.Verbose = false
	// Silence goproxy's internal logger — it spams warnings on shutdown
	gp.Logger = log.New(io.Discard, "", 0)

	// Configure MITM for all HTTPS connections
	tlsCert := cs.TLSCert()
	mitmAction := &goproxy.ConnectAction{
		Action:    goproxy.ConnectMitm,
		TLSConfig: goproxy.TLSConfigFromCA(&tlsCert),
	}
	gp.OnRequest().HandleConnect(goproxy.FuncHttpsHandler(
		func(host string, _ *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
			return mitmAction, host
		},
	))

	// Intercept requests — capture request data, store in context
	gp.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		decision := executionPolicy.AuthorizeHTTPRequest(req, browserCredentialOrigin(req, credentialOrigin))
		policyAllowed := decision.Allowed
		forceFiltered := false
		passiveRender := false
		if !decision.Allowed {
			if allowPassiveRenderDependencyWithRegistry(req, decision, executionPolicy, passiveAssets) {
				// This is a browser-paint dependency, not target evidence. Preserve
				// it for rendering but permanently exclude it from analysis.
				forceFiltered = true
				passiveRender = true
				req = markPassiveRenderDial(req)
				logger.Debug("proxy allowed filtered passive render dependency",
					"url", decision.TargetURL,
					"destination", req.Header.Get("Sec-Fetch-Dest"),
					"referer", req.Header.Get("Referer"),
				)
			} else {
				if audit != nil {
					audit(decision)
				}
				key := strings.Join([]string{string(decision.Code), decision.CanonicalOrigin, decision.Reason}, "|")
				policyLogMu.Lock()
				policyLogCounts[key]++
				count := policyLogCounts[key]
				policyLogMu.Unlock()
				if count == 1 || count == 10 || count == 50 {
					logger.Info("proxy blocked request by policy",
						"code", decision.Code,
						"url", decision.TargetURL,
						"reason", decision.Reason,
						"occurrence_count", count,
					)
				}
				return req, goproxy.NewResponse(req, goproxy.ContentTypeText,
					http.StatusForbidden, "AOBTD policy denied request: "+decision.Reason)
			}
		}
		captured := interceptor.captureRequest(req, forceFiltered)
		ctx.UserData = &proxyCapturedContext{
			captured:      captured,
			policyAllowed: policyAllowed,
			passiveRender: passiveRender,
		}
		return req, nil
	})

	// Intercept responses — pair with captured request, emit traffic entry
	gp.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		if capturedContext, ok := ctx.UserData.(*proxyCapturedContext); ok {
			entry := interceptor.CaptureResponse(capturedContext.captured, resp)
			if capturedContext.policyAllowed {
				passiveAssets.ObserveAuthorizedDocument(entry)
			}
			if capturedContext.passiveRender {
				passiveAssets.ObserveAllowedRedirect(capturedContext.captured, resp)
			}
		}
		return resp
	})

	addr := fmt.Sprintf("%s:%d", listenAddr, port)

	return &Proxy{
		gp:          gp,
		interceptor: interceptor,
		certStore:   cs,
		logger:      logger,
		addr:        addr,
	}, nil
}

// browserCredentialOrigin respects the browser's cookie jar for cookie-only
// requests. Chromium already applies Domain, Path, Secure, and SameSite rules
// before attaching a Cookie header; rebinding that cookie to the actual request
// origin lets an explicitly wildcard-scoped sibling load normally. Stronger
// credentials (Authorization, API keys, CSRF/token headers) remain bound to the
// operator-selected origin and cannot cross hosts implicitly.
func browserCredentialOrigin(req *http.Request, configured string) string {
	if req == nil || req.URL == nil || strings.TrimSpace(req.Header.Get("Cookie")) == "" {
		return configured
	}
	for name, values := range req.Header {
		if len(values) == 0 {
			continue
		}
		normalized := strings.ToLower(strings.ReplaceAll(name, "_", "-"))
		if normalized == "authorization" || normalized == "proxy-authorization" ||
			normalized == "x-api-key" || strings.Contains(normalized, "csrf") ||
			(strings.HasSuffix(normalized, "-token") && normalized != "cookie") {
			return configured
		}
	}
	origin, err := policy.CanonicalOrigin(req.URL.String())
	if err != nil {
		return configured
	}
	return origin.String()
}

// Addr returns the proxy listen address.
func (p *Proxy) Addr() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.addr
}

// Start starts the proxy server. Blocks until ctx is cancelled.
func (p *Proxy) Start(ctx context.Context) error {
	listener, err := net.Listen("tcp", p.addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", p.addr, err)
	}
	return p.Serve(ctx, listener)
}

// Serve runs the proxy on an already-bound listener. UI tools use this to
// reserve an ephemeral port before launching Chromium, eliminating the
// listen/startup race while retaining the exact same policy boundary.
func (p *Proxy) Serve(ctx context.Context, listener net.Listener) error {
	p.mu.Lock()
	if p.running {
		p.mu.Unlock()
		_ = listener.Close()
		return fmt.Errorf("proxy already running")
	}
	p.running = true
	p.addr = listener.Addr().String()
	server := &http.Server{
		Handler: p.gp,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
	p.server = server
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		p.running = false
		p.mu.Unlock()
	}()

	p.logger.Info("proxy started", "addr", listener.Addr().String())

	go func() {
		<-ctx.Done()
		p.logger.Info("shutting down proxy")
		server.Close()
	}()

	err := server.Serve(listener)
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}
