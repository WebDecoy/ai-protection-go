package aiprotection

import (
	"net/http"
	"regexp"
	"strings"
)

var receiptPattern = regexp.MustCompile(`^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`)

func browserReceipt(headers http.Header, property string) string {
	name := "__Host-wd_runtime_" + strings.ToLower(property)
	request := http.Request{Header: headers}
	token := ""
	count := 0
	for _, cookie := range request.Cookies() {
		if cookie.Name == name {
			count++
			token = cookie.Value
		}
	}
	if count != 1 || len(token) > 4096 || !receiptPattern.MatchString(token) {
		return ""
	}
	return token
}
func browserEvidenceCheck(status string, mode Mode) Check {
	check := Check{ID: "browser_evidence", Source: "remote", Mode: mode, Decision: "unavailable", Reason: "browser_evidence_unsupported"}
	switch status {
	case "allow", "challenge":
		check.Decision = status
	case "block":
		check.Decision = "deny"
	case "missing", "invalid":
	default:
		return check
	}
	check.Reason = "browser_evidence_" + status
	return check
}
