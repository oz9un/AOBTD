package agent

import (
	"context"
	"time"
)

// Agent is the interface all agents must implement.
type Agent interface {
	Name() string
	Start(ctx context.Context) error
	Capabilities() []EventType
}

// EventType identifies a category of event on the bus.
type EventType string

const (
	EventTrafficCaptured    EventType = "traffic.captured"
	EventEndpointDiscovered EventType = "endpoint.discovered"
	EventPageCrawled        EventType = "page.crawled"
	EventAuthRequired       EventType = "auth.required"
	EventAuthCompleted      EventType = "auth.completed"
	EventAnalysisComplete   EventType = "analysis.complete"
	EventFindingDetected    EventType = "finding.detected"
	EventHumanHelpNeeded    EventType = "human.help_needed"
	EventScanPhaseChanged   EventType = "scan.phase_changed"
	EventBudgetWarning      EventType = "budget.warning"
	EventReconComplete      EventType = "recon.complete"
)

// Event is a message passed between agents via the event bus.
type Event struct {
	Type      EventType
	Source    string // agent name that emitted this
	Timestamp time.Time
	Payload   any // type-asserted by subscribers
}

// ScanPhase represents the current phase of the scan.
type ScanPhase string

const (
	PhaseDiscovery ScanPhase = "discovery"
	PhaseAuth      ScanPhase = "authentication"
	PhaseDeepCrawl ScanPhase = "deep_crawl"
	PhaseAnalysis      ScanPhase = "analysis"
	PhaseVerification  ScanPhase = "verification"
	PhaseComplete      ScanPhase = "complete"
)

// PageCrawledPayload is the payload for EventPageCrawled.
type PageCrawledPayload struct {
	URL      string
	Links    []string
	Forms    int
	Scripts  int
}

// EndpointPayload is the payload for EventEndpointDiscovered.
type EndpointPayload struct {
	Method     string
	URLPattern string
	HasParams  bool
	HasInput   bool
	IsAPI      bool
}
