// url-clusterer-prototype evaluates whether an LLM can produce better URL
// patterns than our regex normalizer. The regex turns
//    /products/nike-air-max-123 → /products/{slug}
// but misses semantic structure — "{slug}" says nothing about WHAT kind
// of resource this represents. The LLM ought to say "product-detail" and
// group all product pages under one cluster, even if their slug formats
// differ (IDs vs slugs vs hashes).
//
// Usage:
//   go run ./cmd/url-clusterer-prototype --scan 15 --model qwen2.5:14b --sample 60
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ozzyw/aobtd/internal/llm"
	"github.com/ozzyw/aobtd/internal/store"
)

const clustererSystem = `You are a senior pentester triaging a crawl's output. You will receive a flat list of URLs. Your ONLY job is to group them by SEMANTIC purpose and return the clusters as JSON. Do NOT explain individual URLs. Do NOT return a map of URL→description. Return clusters.

Rules:
1. Each URL you see goes into EXACTLY ONE cluster. Do not skip any URL.
2. Aim for 4–12 clusters total. Never one-cluster-per-URL. Never everything-in-one-cluster.
3. Cluster names: short kebab-case labels describing WHAT the page is FOR (e.g. product-detail, user-orders, admin-users, tracking-pixel, auth-login, api-search, cdn-static-asset).
4. pattern: an abstract URL shape covering the cluster, using semantic placeholders like {product_id}, {slug}, {category}, {token}. Prefer meaningful names over generic {id}.
5. pentest_note: one short sentence. What you'd probe here, or "not interesting — ignore".
6. example_urls: up to 3 real URLs from the input that are in this cluster (verbatim).

── EXAMPLE ──

INPUT:
  /product/nike-air-max-123
  /product/adidas-ultra-boost
  /product/puma-rs-x-888
  /admin/users
  /admin/users/1
  /admin/settings
  /api/v2/search?q=shoe
  /api/v2/search?q=shirt
  /static/main.abc123.js
  /static/theme.def456.css
  /track?ev=pageview&uid=42

OUTPUT (exactly this schema, no prose outside):
{
  "clusters": [
    {
      "name": "product-detail",
      "pattern": "/product/{slug}",
      "count": 3,
      "example_urls": ["/product/nike-air-max-123", "/product/adidas-ultra-boost", "/product/puma-rs-x-888"],
      "pentest_note": "read-only product catalog — low priority; check slug accepts special chars"
    },
    {
      "name": "admin-panel",
      "pattern": "/admin/{resource}[/{id}]",
      "count": 3,
      "example_urls": ["/admin/users", "/admin/users/1", "/admin/settings"],
      "pentest_note": "priority target — check authz on every /admin/* path and IDOR on /admin/users/{id}"
    },
    {
      "name": "search-api",
      "pattern": "/api/v2/search?q={query}",
      "count": 2,
      "example_urls": ["/api/v2/search?q=shoe", "/api/v2/search?q=shirt"],
      "pentest_note": "user-controlled q parameter — test for reflected XSS, NoSQLi, SSRF"
    },
    {
      "name": "static-asset",
      "pattern": "/static/{hashed_filename}",
      "count": 2,
      "example_urls": ["/static/main.abc123.js", "/static/theme.def456.css"],
      "pentest_note": "cache-busted CDN assets — ignore"
    },
    {
      "name": "tracking-pixel",
      "pattern": "/track?ev={event}&uid={user_id}",
      "count": 1,
      "example_urls": ["/track?ev=pageview&uid=42"],
      "pentest_note": "analytics beacon — ignore"
    }
  ],
  "total_urls_seen": 11
}

Output ONLY the JSON, no prose, no code fences, no apologies.`

func main() {
	var (
		scanID   int64
		model    string
		provider string
		output   string
		sample   int
		save     string
	)
	flag.Int64Var(&scanID, "scan", 0, "Scan id")
	flag.StringVar(&model, "model", "qwen2.5:14b", "LLM model")
	flag.StringVar(&provider, "provider", "ollama", "Provider")
	flag.StringVar(&output, "output", "./aobtd-output", "Scan output dir")
	flag.IntVar(&sample, "sample", 60, "How many URLs to sample")
	flag.StringVar(&save, "save", "", "Save full output to this file")
	flag.Parse()

	if scanID == 0 {
		fmt.Fprintln(os.Stderr, "--scan required")
		os.Exit(1)
	}

	db, err := store.Open(filepath.Join(output, "scan.db"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer db.Close()

	// Pull a stratified sample: a few per host, preferring ones we haven't
	// seen 100 of already. For fairness across the comparison, we sort by
	// url to make sampling deterministic.
	rows, err := db.Conn().Query(`
		SELECT DISTINCT url FROM traffic
		WHERE scan_id=? AND is_filtered=FALSE
		ORDER BY url ASC`, scanID)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var urls []string
	for rows.Next() {
		var u string
		rows.Scan(&u)
		urls = append(urls, u)
	}
	rows.Close()
	if len(urls) == 0 {
		fmt.Fprintln(os.Stderr, "no URLs for scan")
		os.Exit(1)
	}

	// Sample evenly across the list
	step := len(urls) / sample
	if step < 1 {
		step = 1
	}
	sampled := make([]string, 0, sample)
	for i := 0; i < len(urls) && len(sampled) < sample; i += step {
		u := urls[i]
		// Truncate pathologically long tracking URLs so they don't dominate
		// the prompt. We keep scheme+host+path+first 100 chars of query.
		if len(u) > 180 {
			u = u[:180] + "…"
		}
		sampled = append(sampled, u)
	}
	sort.Strings(sampled)

	user := "INPUT (" + fmt.Sprint(len(sampled)) + " URLs):\n"
	for _, u := range sampled {
		user += u + "\n"
	}
	user += "\nNow emit the JSON clusters array as shown in the example."

	prov, err := llm.NewProvider(provider, "", "", model)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	fmt.Printf("═══ URL clusterer ═══\n")
	fmt.Printf("Scan: #%d  model: %s  sampled: %d/%d URLs\n", scanID, model, len(sampled), len(urls))

	start := time.Now()
	resp, err := prov.Complete(context.Background(), &llm.Request{
		SystemPrompt: clustererSystem,
		Messages:     []llm.Message{{Role: "user", Content: user}},
		Temperature:  0.1,
		MaxTokens:    3000,
		JSONMode:     true,
	})
	dur := time.Since(start)
	if err != nil {
		fmt.Fprintln(os.Stderr, "LLM:", err)
		os.Exit(1)
	}
	fmt.Printf("Response: %d in / %d out tokens · %.2fs\n\n",
		resp.Usage.InputTokens, resp.Usage.OutputTokens, dur.Seconds())

	var parsed struct {
		Clusters []struct {
			Name        string   `json:"name"`
			Pattern     string   `json:"pattern"`
			Count       int      `json:"count"`
			ExampleURLs []string `json:"example_urls"`
			PentestNote string   `json:"pentest_note"`
		} `json:"clusters"`
		TotalURLs int `json:"total_urls_seen"`
	}
	raw := resp.Content
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		// strip prose
		s := strings.Index(raw, "{")
		e := strings.LastIndex(raw, "}")
		if s >= 0 && e > s {
			json.Unmarshal([]byte(raw[s:e+1]), &parsed)
		}
	}

	fmt.Printf("─── %d clusters ──\n", len(parsed.Clusters))
	for _, c := range parsed.Clusters {
		fmt.Printf("\n[%s] %s (%d URLs)\n", c.Name, c.Pattern, c.Count)
		if c.PentestNote != "" {
			fmt.Printf("  note: %s\n", c.PentestNote)
		}
		for i, e := range c.ExampleURLs {
			if i >= 3 {
				break
			}
			fmt.Printf("  ex: %s\n", e)
		}
	}

	if save != "" {
		b, _ := json.MarshalIndent(map[string]any{
			"meta": map[string]any{
				"model":      model,
				"scan_id":    scanID,
				"sampled":    len(sampled),
				"total_urls": len(urls),
				"duration_s": dur.Seconds(),
				"tokens_in":  resp.Usage.InputTokens,
				"tokens_out": resp.Usage.OutputTokens,
			},
			"raw":    resp.Content,
			"parsed": parsed,
		}, "", "  ")
		os.WriteFile(save, b, 0o644)
		fmt.Printf("\nSaved to %s\n", save)
	}
}
