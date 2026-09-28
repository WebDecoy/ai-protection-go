package aiprotection

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

type account struct {
	Schema         int    `json:"schema"`
	PropertyID     string `json:"property_id"`
	OrganizationID string `json:"organization_id"`
	Mode           Mode   `json:"mode"`
	Observe        *bool  `json:"observe"`
	Enforce        *bool  `json:"enforce"`
	status         string
}

func (c *Client[T]) binding(ctx context.Context) account {
	c.mu.Lock()
	if c.now().Before(c.until) {
		a := c.cached
		c.mu.Unlock()
		return a
	}
	if pending := c.pending; pending != nil {
		c.mu.Unlock()
		select {
		case <-pending:
			return c.binding(ctx)
		case <-ctx.Done():
			return account{status: "unavailable"}
		}
	}
	pending := make(chan struct{})
	c.pending = pending
	c.mu.Unlock()
	a := account{status: "unavailable"}
	callCtx, cancel := context.WithTimeout(ctx, c.config.DetectorTimeout)
	defer cancel()
	if c.json(callCtx, http.MethodGet, "/api/v1/sdk/ai-abuse/config", nil, &a) == nil && a.Schema == 1 && validUUID(a.PropertyID) && validUUID(a.OrganizationID) && a.Observe != nil && *a.Observe && a.Enforce != nil && validMode(a.Mode) {
		a.status = "property_mismatch"
		if strings.EqualFold(a.PropertyID, c.config.PropertyID) {
			a.status = "verified"
		}
	} else {
		a = account{status: "unavailable"}
	}
	ttl := 5 * time.Second
	if a.status == "verified" {
		ttl = 60 * time.Second
	}
	c.mu.Lock()
	c.cached = a
	c.until = c.now().Add(ttl)
	c.pending = nil
	close(pending)
	c.mu.Unlock()
	return a
}
func (c *Client[T]) json(ctx context.Context, method, path string, payload any, out any) error {
	var body []byte
	var err error
	if payload != nil {
		body, err = json.Marshal(payload)
		if err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.config.BaseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.config.APIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-WebDecoy-Property-ID", c.config.PropertyID)
	response, err := c.http.Do(req)
	if err != nil {
		return errors.New("WebDecoy transport unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return errors.New("WebDecoy HTTP error")
	}
	if out == nil {
		_, err = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return err
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	if err != nil || len(raw) > 65536 {
		return errors.New("invalid WebDecoy response")
	}
	return json.Unmarshal(raw, out)
}
func (c *Client[T]) detect(ctx context.Context, r Request, id string, mode Mode) (string, string, error) {
	ctx, cancel := context.WithTimeout(ctx, c.config.DetectorTimeout)
	defer cancel()
	names := []string{}
	for name := range r.Headers {
		names = append(names, strings.ToLower(name))
	}
	sort.Strings(names)
	payload := map[string]any{"decision_mode": "unified_v1", "ai_admission": map[string]any{"request_id": id, "mode": mode},
		"request_metadata": map[string]any{"method": r.Method, "path": r.Route, "ip": r.IP.Unmap().String(), "user_agent": r.Headers.Get("User-Agent"), "timestamp": c.now().UnixMilli()},
		"cs":               map[string]any{"hn": names, "al": r.Headers.Get("Accept-Language"), "ae": r.Headers.Get("Accept-Encoding")}, "local_analysis": map[string]any{"needs_verification": true}}
	if c.config.BrowserEvidenceOrigin != "" {
		token := r.BrowserEvidence
		if token == "" {
			token = browserReceipt(r.Headers, c.config.PropertyID)
		}
		if len(token) > 4096 || !receiptPattern.MatchString(token) {
			token = ""
		}
		payload["browser_evidence"] = map[string]string{"origin": c.config.BrowserEvidenceOrigin, "token": token}
	}
	var result struct {
		BrowserEvidence string `json:"browser_evidence"`
		Decision        string `json:"decision"`
		Mode            string `json:"decision_mode"`
	}
	if err := c.json(ctx, http.MethodPost, "/api/v1/sdk/detect", payload, &result); err != nil {
		return "", "", err
	}
	if result.Mode != "unified_v1" || (result.Decision != "allow" && result.Decision != "block" && result.Decision != "challenge") {
		return "", "", errors.New("unsupported detection response")
	}
	return result.Decision, result.BrowserEvidence, nil
}
