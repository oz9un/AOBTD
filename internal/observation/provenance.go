package observation

import (
	"net/url"
	"strings"
	"sync"

	"github.com/ozzyw/aobtd/pkg/types"
)

// Provenance identifies the agent action that caused an HTTP observation.
// SourceActionID refers to a persisted follow-up/action row when one exists;
// HypothesisID identifies the strategist hypothesis that action was testing.
type Provenance struct {
	SourceAgent    string
	SourceActionID int64
	HypothesisID   string
}

// ProvenanceResolver snapshots the provenance active when a request begins.
// The request URL and Referer disambiguate concurrent page actions.
type ProvenanceResolver func(requestURL, referer string) Provenance

// Normalize returns a safe, persistence-ready provenance value.
func (p Provenance) Normalize() Provenance {
	p.SourceAgent = strings.TrimSpace(p.SourceAgent)
	if p.SourceAgent == "" {
		p.SourceAgent = "capture"
	}
	if p.SourceActionID < 0 {
		p.SourceActionID = 0
	}
	p.HypothesisID = strings.TrimSpace(p.HypothesisID)
	return p
}

// Apply copies provenance onto a captured traffic entry.
func (p Provenance) Apply(entry *types.TrafficEntry) {
	if entry == nil {
		return
	}
	p = p.Normalize()
	entry.SourceAgent = p.SourceAgent
	entry.SourceActionID = p.SourceActionID
	entry.HypothesisID = p.HypothesisID
}

// ProvenanceTracker holds the provenance for the currently active browser
// operation. Frames make nested operations safe and allow cleanup to happen
// out of order without restoring stale state.
type ProvenanceTracker struct {
	mu     sync.RWMutex
	nextID uint64
	frames []provenanceFrame
}

type provenanceFrame struct {
	id         uint64
	provenance Provenance
	targetURL  string
}

// NewProvenanceTracker creates an empty tracker. Its snapshot defaults to the
// passive "capture" source until an agent begins an attributed operation.
func NewProvenanceTracker() *ProvenanceTracker {
	return &ProvenanceTracker{}
}

// Begin makes p active and returns an idempotent cleanup function.
func (t *ProvenanceTracker) Begin(p Provenance) func() {
	return t.begin(p, "")
}

// BeginTargeted activates provenance for an action aimed at targetURL.
// Concurrent browser tabs can then be disambiguated by request URL/Referer.
func (t *ProvenanceTracker) BeginTargeted(p Provenance, targetURL string) func() {
	return t.begin(p, canonicalProvenanceURL(targetURL))
}

func (t *ProvenanceTracker) begin(p Provenance, targetURL string) func() {
	if t == nil {
		return func() {}
	}
	p = p.Normalize()
	t.mu.Lock()
	t.nextID++
	id := t.nextID
	t.frames = append(t.frames, provenanceFrame{id: id, provenance: p, targetURL: targetURL})
	t.mu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			t.mu.Lock()
			defer t.mu.Unlock()
			for index := len(t.frames) - 1; index >= 0; index-- {
				if t.frames[index].id != id {
					continue
				}
				t.frames = append(t.frames[:index], t.frames[index+1:]...)
				return
			}
		})
	}
}

// Snapshot returns the most recently activated provenance frame.
func (t *ProvenanceTracker) Snapshot() Provenance {
	if t == nil {
		return Provenance{}.Normalize()
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	if len(t.frames) == 0 {
		return Provenance{}.Normalize()
	}
	return t.frames[len(t.frames)-1].provenance
}

// AgentSnapshot returns the most recently activated agent-level frame while
// ignoring any concurrently active action frames.
func (t *ProvenanceTracker) AgentSnapshot() Provenance {
	if t == nil {
		return Provenance{}.Normalize()
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	for index := len(t.frames) - 1; index >= 0; index-- {
		if t.frames[index].provenance.SourceActionID == 0 {
			return t.frames[index].provenance
		}
	}
	return Provenance{}.Normalize()
}

// SnapshotForRequest resolves concurrent action frames conservatively. With a
// single active action, every emitted request belongs to it. With concurrent
// actions, only the action whose target matches the request URL or Referer is
// selected; ambiguous subresources fall back to agent-level provenance.
func (t *ProvenanceTracker) SnapshotForRequest(requestURL, referer string) Provenance {
	if t == nil {
		return Provenance{}.Normalize()
	}
	requestURL = canonicalProvenanceURL(requestURL)
	referer = canonicalProvenanceURL(referer)
	t.mu.RLock()
	defer t.mu.RUnlock()

	base := Provenance{}.Normalize()
	actionCount := 0
	var onlyAction Provenance
	for index := len(t.frames) - 1; index >= 0; index-- {
		frame := t.frames[index]
		if frame.provenance.SourceActionID == 0 {
			if base.SourceAgent == "capture" {
				base = frame.provenance
			}
			continue
		}
		actionCount++
		onlyAction = frame.provenance
		if frame.targetURL != "" &&
			(frame.targetURL == requestURL || frame.targetURL == referer) {
			return frame.provenance
		}
	}
	if actionCount == 1 {
		return onlyAction
	}
	return base
}

func canonicalProvenanceURL(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	parsed.Host = strings.ToLower(parsed.Host)
	parsed.Fragment = ""
	return parsed.String()
}
