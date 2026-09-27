package aiprotection

import (
	"context"
	"log"
	"net/http"
	"sync"
	"time"
)

type Report struct {
	Schema           int       `json:"schema"`
	RequestID        string    `json:"request_id"`
	Timestamp        time.Time `json:"timestamp"`
	Decision         string    `json:"decision"`
	Reason           string    `json:"reason"`
	Degraded         bool      `json:"degraded"`
	Checks           []Check   `json:"checks"`
	HandlerAttempted bool      `json:"handler_attempted"`
	HandlerStatus    *int      `json:"handler_status,omitempty"`
	Action           string    `json:"action"`
}
type Outcome struct {
	HandlerAttempted bool
	Status           int
	Cancelled        bool
	HandlerError     bool
}

func cloneReport(r Report) Report {
	r.Checks = append([]Check(nil), r.Checks...)
	if r.HandlerStatus != nil {
		s := *r.HandlerStatus
		r.HandlerStatus = &s
	}
	return r
}

// Report queues one best-effort outcome without waiting for HTTP or custom sinks.
// False means a foreign/duplicate decision or a full queue. Dropped reports aren't retried.
func (c *Client[T]) Report(d *Decision, outcome Outcome) bool {
	if d == nil || d.owner != c {
		return false
	}
	accepted := false
	d.once.Do(func() {
		c.reportMu.Lock()
		if c.inFlight >= c.config.MaxPendingReports {
			c.reportMu.Unlock()
			log.Print("WebDecoy report dropped: queue full")
			return
		}
		if c.inFlight == 0 {
			c.idle = make(chan struct{})
		}
		c.inFlight++
		c.reportMu.Unlock()
		accepted = true
		report := cloneReport(d.report)
		report.HandlerAttempted = outcome.HandlerAttempted
		if outcome.Status >= 100 && outcome.Status <= 599 {
			status := outcome.Status
			report.HandlerStatus = &status
		}
		if outcome.Cancelled {
			report.Action = "cancelled"
		} else if outcome.HandlerError {
			report.Action = "handler_error"
		}
		go func() {
			defer func() {
				c.reportMu.Lock()
				c.inFlight--
				if c.inFlight == 0 {
					close(c.idle)
				}
				c.reportMu.Unlock()
			}()
			ctx, cancel := context.WithTimeout(context.Background(), c.config.ReportingTimeout)
			defer cancel()
			var wg sync.WaitGroup
			run := func(f func() error) {
				wg.Add(1)
				go func() {
					defer wg.Done()
					defer func() {
						if recover() != nil {
							log.Print("WebDecoy reporting sink panicked")
						}
					}()
					if err := f(); err != nil {
						log.Print("WebDecoy report delivery failed")
					}
				}()
			}
			if !c.config.DisableCentralReporting {
				run(func() error {
					return c.json(ctx, http.MethodPost, "/api/v1/sdk/ai-abuse/reports", cloneReport(report), nil)
				})
			}
			if sink := c.config.OnReport; sink != nil {
				run(func() error { return sink(ctx, cloneReport(report)) })
			}
			wg.Wait()
		}()
	})
	return accepted
}

// Flush waits for queued reports. Call after draining HTTP handlers at shutdown.
// The context bounds waiting even if a custom sink ignores its timeout.
func (c *Client[T]) Flush(ctx context.Context) error {
	c.reportMu.Lock()
	idle := c.idle
	c.reportMu.Unlock()
	select {
	case <-idle:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
