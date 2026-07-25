// promptshot renders the interactive-login prompt modal in headless
// Chrome and screenshots it. Used to verify the login_found payload's
// new screenshot_url renders correctly in the modal.
//
//   go run ./cmd/promptshot --ui http://127.0.0.1:8097 --out docs/screenshots/prompt-login.png
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
)

func main() {
	ui := flag.String("ui", "http://127.0.0.1:8097", "Dev UI base URL (must point at a scan that has a login_found prompt)")
	out := flag.String("out", "docs/screenshots/prompt-login.png", "Output PNG path")
	flag.Parse()

	l := launcher.New().
		Leakless(false).
		Headless(true).
		Set("disable-gpu").
		Set("no-first-run").
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

	page, err := browser.Page(proto.TargetCreateTarget{URL: *ui + "/"})
	if err != nil {
		log.Fatalf("page: %v", err)
	}
	_ = page.SetViewport(&proto.EmulationSetDeviceMetricsOverride{
		Width: 900, Height: 900, DeviceScaleFactor: 1.5,
	})
	_ = page.WaitLoad()
	time.Sleep(900 * time.Millisecond)

	// Hydrate the SPA against scan id 1 and pop the prompt modal. We call
	// renderPromptModal() with the payload pulled from the /api/prompts
	// endpoint — this exercises the exact render path the bell icon uses.
	_, err = page.Eval(`async () => {
		scanID = 1;
		cache = {};
		try { resetViewCaches(); } catch(e){}
		try { await refreshAll(); } catch(e){}
		const prompts = await (await fetch('/api/prompts')).json();
		if (!prompts || !prompts.length) throw new Error('no prompts returned by /api/prompts');
		// The UI keeps prompts in _promptCache and openPromptModal(id) looks them
		// up there; hydrate it so the modal opens for our seeded row.
		_promptCache = prompts;
		openPromptModal(prompts[0].id);
		return prompts[0].kind;
	}`)
	if err != nil {
		log.Fatalf("open prompt modal: %v", err)
	}
	time.Sleep(600 * time.Millisecond)

	buf, err := page.Screenshot(false, &proto.PageCaptureScreenshot{
		Format:                proto.PageCaptureScreenshotFormatPng,
		CaptureBeyondViewport: false,
	})
	if err != nil {
		log.Fatalf("screenshot: %v", err)
	}
	if err := os.WriteFile(*out, buf, 0o644); err != nil {
		log.Fatalf("write: %v", err)
	}
	fmt.Printf("wrote %s (%d KB)\n", *out, len(buf)/1024)
}
