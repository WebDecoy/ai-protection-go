// Local fixture only: no live model call, user store or production auth integration.
package main

import (
	"context"
	"encoding/json"
	protection "github.com/WebDecoy/ai-protection-go"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

type userContext struct {
	Plan        string
	InputLength int
}

func main() {
	token := os.Getenv("EXAMPLE_TOKEN")
	if token == "" {
		log.Fatal("EXAMPLE_TOKEN required")
	}
	client, err := protection.New(protection.Config[userContext]{BaseURL: os.Getenv("WEBDECOY_URL"), APIKey: os.Getenv("WEBDECOY_KEY"), PropertyID: os.Getenv("WEBDECOY_PROPERTY_ID"), Mode: protection.Observe,
		Rules: []protection.Rule[userContext]{{ID: "plan_input_limit", Mode: protection.Enforce, Evaluate: func(u userContext) (protection.RuleResult, error) {
			return protection.RuleResult{Allowed: u.Plan == "paid" || u.InputLength <= 1000, Reason: "plan_input_limit"}, nil
		}}}})
	if err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /chat", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "unauthorized", 401)
			return
		}
		var input struct {
			Prompt string `json:"prompt"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 8192)
		if json.NewDecoder(r.Body).Decode(&input) != nil || strings.TrimSpace(input.Prompt) == "" || len(input.Prompt) > 4000 {
			http.Error(w, "invalid input", 400)
			return
		}
		// Direct loopback fixture. In production, resolve the client through your trusted ingress.
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		ip, _ := netip.ParseAddr(host)
		metadata := protection.Request{IP: ip, Method: r.Method, Route: "/chat", Headers: r.Header}
		// Demo plan is server-owned. Never use a client-supplied plan/user claim.
		err := client.Protect(w, r, metadata, userContext{Plan: "free", InputLength: len(input.Prompt)}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			w.Write([]byte("data: Local model fixture response\n\n"))
			http.NewResponseController(w).Flush()
		}))
		if err != nil && r.Context().Err() == nil {
			http.Error(w, "protection configuration error", 500)
		}
	})
	server := &http.Server{Addr: "127.0.0.1:8091", Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Print(err)
			stop <- syscall.SIGTERM
		}
	}()
	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Print(err)
	}
	if err := client.Flush(ctx); err != nil {
		log.Print(err)
	}
}
