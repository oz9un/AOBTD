package agent

import (
	"log/slog"
	"sync"
	"time"
)

// Bus is a typed pub/sub event bus using Go channels.
type Bus struct {
	mu          sync.RWMutex
	subscribers map[EventType][]chan Event
	logger      *slog.Logger
}

// NewBus creates a new event bus.
func NewBus(logger *slog.Logger) *Bus {
	return &Bus{
		subscribers: make(map[EventType][]chan Event),
		logger:      logger,
	}
}

// Subscribe returns a channel that receives events of the given type.
// The channel is buffered (64) to avoid blocking publishers.
func (b *Bus) Subscribe(eventType EventType) <-chan Event {
	b.mu.Lock()
	defer b.mu.Unlock()

	ch := make(chan Event, 64)
	b.subscribers[eventType] = append(b.subscribers[eventType], ch)
	return ch
}

// Publish sends an event to all subscribers of that event type.
// Non-blocking — if a subscriber's channel is full, the event is dropped
// for that subscriber (logged as a warning).
func (b *Bus) Publish(event Event) {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	b.mu.RLock()
	subs := b.subscribers[event.Type]
	b.mu.RUnlock()

	for _, ch := range subs {
		select {
		case ch <- event:
		default:
			b.logger.Warn("event dropped (subscriber full)",
				"type", event.Type,
				"source", event.Source,
			)
		}
	}
}

// Close closes all subscriber channels.
func (b *Bus) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()

	for _, subs := range b.subscribers {
		for _, ch := range subs {
			close(ch)
		}
	}
	b.subscribers = make(map[EventType][]chan Event)
}
