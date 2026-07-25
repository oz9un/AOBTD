// screenshot is a small dev helper: it points headless Chrome at a running
// `aobtd ui --dev` server, walks each redesigned view, and dumps PNGs into
// docs/screenshots/. Used during the DEMOLABS UI rebuild to verify the
// new Changes / Knowledge / Chains views render without errors and look
// the way we intend before committing.
//
// Usage:
//   go run ./cmd/screenshot --ui http://127.0.0.1:8095 --scan 80 --out docs/screenshots
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
)

type shot struct {
	name      string // file basename without extension
	view      string // currentView value the SPA expects
	wait      time.Duration
	clickSel  string // optional: selector to click before screenshot (e.g., expand a diff)
	scrollSel string // optional: scroll to this selector first
}

func main() {
	uiURL := flag.String("ui", "http://127.0.0.1:8095", "Running aobtd UI base URL")
	scanID := flag.Int("scan", 80, "Scan id to load before navigating views")
	out := flag.String("out", "docs/screenshots", "Directory to write PNGs into")
	width := flag.Int("w", 1480, "Viewport width")
	height := flag.Int("h", 900, "Viewport height")
	flag.Parse()

	if err := os.MkdirAll(*out, 0o755); err != nil {
		log.Fatalf("mkdir %s: %v", *out, err)
	}

	// Headless Chrome — no proxy, no extra flags. We just want to render
	// the SPA against the dev UI and screenshot.
	l := launcher.New().
		Leakless(false).
		Headless(true).
		Set("disable-gpu").
		Set("no-first-run").
		Set("no-default-browser-check").
		Set("hide-scrollbars")
	controlURL, err := l.Launch()
	if err != nil {
		log.Fatalf("launcher: %v", err)
	}
	defer l.Cleanup()

	browser := rod.New().ControlURL(controlURL)
	if err := browser.Connect(); err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer browser.Close()

	page, err := browser.Page(proto.TargetCreateTarget{URL: *uiURL + "/"})
	if err != nil {
		log.Fatalf("page: %v", err)
	}
	if err := page.SetViewport(&proto.EmulationSetDeviceMetricsOverride{
		Width: *width, Height: *height, DeviceScaleFactor: 1.5,
	}); err != nil {
		log.Fatalf("viewport: %v", err)
	}
	if err := page.WaitLoad(); err != nil {
		log.Fatalf("wait load: %v", err)
	}
	// Give the SPA's bootstrap (scan picker fetch, etc.) a beat to settle.
	time.Sleep(900 * time.Millisecond)

	// Wire a console-error sink so we can surface JS exceptions per view.
	// (Done via Eval rather than rod's runtime listener to keep this thin.)
	_, _ = page.Eval(`() => {
		window.__aobtdConsoleErrs = [];
		const orig = console.error;
		console.error = function() {
			try { window.__aobtdConsoleErrs.push(Array.from(arguments).map(String).join(' ')); } catch(e){}
			orig.apply(console, arguments);
		};
		window.addEventListener('error', e => { window.__aobtdConsoleErrs.push('[uncaught] ' + (e.error && e.error.stack || e.message)); });
	}`)

	// Force the SPA onto the scan we want and *await* the cache hydration
	// — selectScan kicks off refreshAll() async and returns; the nav click
	// handler also short-circuits on missing cache, so we manage the
	// lifecycle ourselves to keep the screenshot deterministic.
	_, err = page.Eval(fmt.Sprintf(`async () => {
		scanID = %d;
		cache = {};
		try { resetViewCaches(); } catch(e) {}
		await refreshAll();
		return true;
	}`, *scanID))
	if err != nil {
		log.Fatalf("hydrate scan: %v", err)
	}

	shots := []shot{
		{name: "01-home", view: "home", wait: 600 * time.Millisecond},
		{name: "02-overview", view: "overview", wait: 1200 * time.Millisecond},
		{name: "03-endpoints", view: "endpoints", wait: 700 * time.Millisecond},
		{name: "04-knowledge", view: "knowledge", wait: 700 * time.Millisecond},
		{name: "05-findings", view: "findings", wait: 700 * time.Millisecond},
		{name: "06-chains", view: "chains", wait: 700 * time.Millisecond},
		{name: "07-strategy", view: "strategy", wait: 2500 * time.Millisecond}, // /api/strategy is slow on big scans
		{name: "08-changes", view: "changes", wait: 1400 * time.Millisecond},   // changes hits its own /api endpoint
		{name: "09-graph", view: "graph", wait: 2200 * time.Millisecond},
		{name: "10-traffic", view: "traffic", wait: 900 * time.Millisecond},
		{name: "11-ailog", view: "ailog", wait: 900 * time.Millisecond},
		{name: "12-live", view: "live", wait: 900 * time.Millisecond},
	}

	failed := 0
	for _, s := range shots {
		// Drive the view directly: set currentView, mark the nav item active
		// (visual only), then call renderView(). This avoids the home-mode
		// sidebar collapse hiding the nav items we'd otherwise click on.
		js := fmt.Sprintf(`() => {
			currentView = %q;
			document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
			const nav = document.querySelector('.nav-item[data-view=%q]');
			if (nav) nav.classList.add('active');
			try { closeDetail(); } catch(e){}
			renderView();
			return true;
		}`, s.view, s.view)
		if _, err := page.Eval(js); err != nil {
			log.Printf("[%s] eval failed: %v", s.name, err)
			failed++
			continue
		}
		time.Sleep(s.wait)

		errs, _ := page.Eval(`() => JSON.stringify(window.__aobtdConsoleErrs || [])`)
		if errs != nil {
			s2 := errs.Value.String()
			if s2 != "[]" && s2 != "" && s2 != "\"[]\"" {
				log.Printf("[%s] console errors: %s", s.name, s2)
			}
		}

		path := filepath.Join(*out, s.name+".png")
		buf, err := page.Screenshot(false, &proto.PageCaptureScreenshot{
			Format:                proto.PageCaptureScreenshotFormatPng,
			CaptureBeyondViewport: true,
		})
		if err != nil {
			log.Printf("[%s] screenshot failed: %v", s.name, err)
			failed++
			continue
		}
		if err := os.WriteFile(path, buf, 0o644); err != nil {
			log.Printf("[%s] write failed: %v", s.name, err)
			failed++
			continue
		}
		fmt.Printf("[ok] %s -> %s (%d KB)\n", s.view, path, len(buf)/1024)
	}

	if failed > 0 {
		log.Fatalf("%d screenshot(s) failed", failed)
	}
	fmt.Printf("\n%d screenshots written to %s\n", len(shots), *out)
}
