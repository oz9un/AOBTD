package agent

import (
	"sync"

	"github.com/ozzyw/aobtd/internal/extract"
	"github.com/ozzyw/aobtd/pkg/types"
)

// SharedState holds the shared mutable state for all agents.
type SharedState struct {
	mu               sync.RWMutex
	model            *types.AppModel
	phase            ScanPhase
	appUnderstanding *extract.AppUnderstanding
}

// NewSharedState creates a new shared state for a scan target.
func NewSharedState(target string) *SharedState {
	return &SharedState{
		model: &types.AppModel{
			Target: target,
		},
		phase: PhaseDiscovery,
	}
}

// UpdateModel applies a mutation to the AppModel under a write lock.
func (s *SharedState) UpdateModel(fn func(*types.AppModel)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(s.model)
}

// ReadModel returns a copy of the current AppModel.
func (s *SharedState) ReadModel() types.AppModel {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Shallow copy — slices still share backing arrays, but that's fine
	// for read-only access between lock/unlock.
	copy := *s.model
	return copy
}

// SetPhase changes the current scan phase.
func (s *SharedState) SetPhase(phase ScanPhase) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.phase = phase
}

// Phase returns the current scan phase.
func (s *SharedState) Phase() ScanPhase {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.phase
}

// AddEndpoint adds or updates an endpoint in the model.
func (s *SharedState) AddEndpoint(ep types.Endpoint) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, existing := range s.model.Endpoints {
		if existing.ID == ep.ID {
			s.model.Endpoints[i].HitCount++
			return
		}
	}
	s.model.Endpoints = append(s.model.Endpoints, ep)
}

// AddFinding adds a finding to the model.
func (s *SharedState) AddFinding(f types.Finding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.model.Findings = append(s.model.Findings, f)
}

// SetTechStack updates the detected tech stack.
func (s *SharedState) SetTechStack(ts types.TechStack) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.model.TechStack = ts
}

// EndpointCount returns the number of discovered endpoints.
func (s *SharedState) EndpointCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.model.Endpoints)
}

// SetAppUnderstanding updates the application understanding model.
func (s *SharedState) SetAppUnderstanding(u *extract.AppUnderstanding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.appUnderstanding = u
}

// GetAppUnderstanding returns the current app understanding (or nil).
func (s *SharedState) GetAppUnderstanding() *extract.AppUnderstanding {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.appUnderstanding
}
