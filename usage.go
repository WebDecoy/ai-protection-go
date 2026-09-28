package aiprotection

import (
	"context"
	"log"
	"time"
)

// UsageReport records a provider-hook claim. It never includes provider content,
// raw subject identity or errors, and never changes admission/accounting.
type UsageReport struct {
	Schema         int       `json:"schema"`
	CallID         string    `json:"call_id"`
	Phase          string    `json:"phase"`
	RequestID      string    `json:"request_id,omitempty"`
	ReservationID  string    `json:"reservation_id,omitempty"`
	Timestamp      time.Time `json:"timestamp"`
	RuleID         string    `json:"rule_id"`
	Mode           Mode      `json:"mode"`
	Reason         string    `json:"reason"`
	Started        bool      `json:"started"`
	WouldDeny      bool      `json:"would_deny"`
	PriceID        string    `json:"price_id"`
	InputRate      int64     `json:"input_rate"`
	OutputRate     int64     `json:"output_rate"`
	ReservedTokens int64     `json:"reserved_tokens"`
	ReservedMicros int64     `json:"reserved_micros"`
	InputTokens    *int64    `json:"input_tokens,omitempty"`
	OutputTokens   *int64    `json:"output_tokens,omitempty"`
	CostMicros     *int64    `json:"cost_micros,omitempty"`
}

func (c *Client[T]) reportUsage(report UsageReport) {
	if c.config.DisableCentralReporting {
		return
	}
	c.reportMu.Lock()
	if c.inFlight >= c.config.MaxPendingReports {
		c.reportMu.Unlock()
		log.Print("WebDecoy usage report dropped: queue full")
		return
	}
	if c.inFlight == 0 {
		c.idle = make(chan struct{})
	}
	c.inFlight++
	c.reportMu.Unlock()
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
		if c.json(ctx, "POST", "/api/v1/sdk/ai-abuse/usage", report, nil) != nil {
			log.Print("WebDecoy usage report delivery failed")
		}
	}()
}
