package cli

import (
	"log/slog"
	"sync"
	"time"

	"github.com/ozzyw/aobtd/internal/store"
	"github.com/ozzyw/aobtd/pkg/types"
)

const (
	trafficWriterQueueSize  = 1024
	trafficWriterBatchSize  = 64
	trafficWriterFlushEvery = 25 * time.Millisecond
)

type trafficCaptureWriter struct {
	db     *store.DB
	scanID int64
	logger *slog.Logger
	queue  chan *types.TrafficEntry
	stop   chan struct{}
	done   chan struct{}
	once   sync.Once
	mu     sync.RWMutex
	closed bool
}

func newTrafficCaptureWriter(db *store.DB, scanID int64, logger *slog.Logger) *trafficCaptureWriter {
	w := &trafficCaptureWriter{
		db: db, scanID: scanID, logger: logger,
		queue: make(chan *types.TrafficEntry, trafficWriterQueueSize),
		stop:  make(chan struct{}), done: make(chan struct{}),
	}
	go w.run()
	return w
}

func (w *trafficCaptureWriter) Enqueue(entry *types.TrafficEntry) {
	if entry == nil {
		return
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.closed {
		return
	}
	w.queue <- entry
}

func (w *trafficCaptureWriter) Close() {
	w.once.Do(func() {
		w.mu.Lock()
		w.closed = true
		close(w.stop)
		w.mu.Unlock()
	})
	<-w.done
}

func (w *trafficCaptureWriter) run() {
	defer close(w.done)
	ticker := time.NewTicker(trafficWriterFlushEvery)
	defer ticker.Stop()
	batch := make([]*types.TrafficEntry, 0, trafficWriterBatchSize)
	captured := 0
	flush := func() {
		if len(batch) == 0 {
			return
		}
		written, err := w.db.InsertTrafficBatch(w.scanID, batch)
		if err != nil {
			w.logger.Error("store traffic batch failed", "error", err, "batch_size", len(batch))
			// Preserve valid captures when one malformed entry poisons a batch.
			written = 0
			for _, entry := range batch {
				if _, itemErr := w.db.InsertTraffic(w.scanID, entry); itemErr != nil {
					w.logger.Error("store traffic failed", "error", itemErr, "url", entry.Request.URL)
					continue
				}
				written++
			}
		}
		captured += written
		if captured > 0 && captured%25 < written {
			w.logger.Info("traffic captured", "count", captured)
		}
		batch = batch[:0]
	}

	for {
		select {
		case entry := <-w.queue:
			batch = append(batch, entry)
			if len(batch) >= trafficWriterBatchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-w.stop:
			for {
				select {
				case entry := <-w.queue:
					batch = append(batch, entry)
					if len(batch) >= trafficWriterBatchSize {
						flush()
					}
				default:
					flush()
					return
				}
			}
		}
	}
}
