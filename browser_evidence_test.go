package aiprotection

import (
	"net/http"
	"strings"
	"testing"
)

func TestBrowserEvidenceCookieSelectionAndStatus(t *testing.T) {
	p := "11111111-1111-4111-8111-111111111111"
	name := "__Host-wd_runtime_" + p
	h := http.Header{"Cookie": []string{"private_session=secret; " + name + "=payload.signature"}}
	if browserReceipt(h, p) != "payload.signature" {
		t.Fatal("receipt missing")
	}
	h.Set("Cookie", name+"=a.b; "+name+"=c.d")
	if browserReceipt(h, p) != "" {
		t.Fatal("ambiguous cookie")
	}
	h.Set("Cookie", name+"="+strings.Repeat("a", 4097))
	if browserReceipt(h, p) != "" {
		t.Fatal("unbounded receipt")
	}
	for _, status := range []string{"invalid", "missing", ""} {
		if browserEvidenceCheck(status, Enforce).Decision != "unavailable" {
			t.Fatal(status)
		}
	}
	if browserEvidenceCheck("block", Observe).Decision != "deny" {
		t.Fatal("lost observed risk")
	}
	for _, origin := range []string{"http://owned.test", "https://owned.test/path", "https://owned.test/", "https://u:p@owned.test"} {
		if _, e := New(Config[string]{BaseURL: "https://ingest.test", APIKey: "key", PropertyID: p, BrowserEvidenceOrigin: origin}); e == nil {
			t.Fatal(origin)
		}
	}
}
