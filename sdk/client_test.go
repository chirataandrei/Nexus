package nexussdk

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// newMockNexus simulates the Nexus gateway: it issues "fixture" tokens
// (not real JWTs — the SDK client doesn't care about the format, only
// the contract) and exposes a protected upstream that requires the
// correct Authorization header.
func newMockNexus(t *testing.T, ttl time.Duration) (*httptest.Server, *int32) {
	t.Helper()
	var tokenRequests int32
	currentToken := "token-v0"

	mux := http.NewServeMux()
	mux.HandleFunc("/nexus/identity/token", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&tokenRequests, 1)
		var req tokenRequest
		_ = json.NewDecoder(r.Body).Decode(&req)

		n := atomic.LoadInt32(&tokenRequests)
		currentToken = "token-v" + time.Now().Format("150405.000000") + "-" + string(rune('0'+n))

		resp := tokenResponse{
			Token:     currentToken,
			SpiffeID:  "spiffe://nexus.trust/agent/" + req.AgentID + "/task/" + req.TaskID,
			Scopes:    req.Scopes,
			IssuedAt:  time.Now().Unix(),
			ExpiresAt: time.Now().Add(ttl).Unix(),
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/v1/protected", func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer "+currentToken {
			http.Error(w, "invalid or expired token", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	srv := httptest.NewServer(mux)
	return srv, &tokenRequests
}

func TestClient_Token_FetchesAndCaches(t *testing.T) {
	srv, tokenRequests := newMockNexus(t, 5*time.Minute)
	defer srv.Close()

	c := New(srv.URL, "agent-1", "secret", "task-1")

	tok1, err := c.Token(context.Background())
	if err != nil {
		t.Fatalf("Token failed: %v", err)
	}
	tok2, err := c.Token(context.Background())
	if err != nil {
		t.Fatalf("Token (second call) failed: %v", err)
	}
	if tok1 != tok2 {
		t.Errorf("the token should be cached between calls, got %q and %q", tok1, tok2)
	}
	if got := atomic.LoadInt32(tokenRequests); got != 1 {
		t.Errorf("expected exactly 1 token request, observed %d", got)
	}
}

func TestClient_Token_RefreshesWhenNearExpiry(t *testing.T) {
	// TTL shorter than the refresh margin (30s) => every call refreshes.
	srv, tokenRequests := newMockNexus(t, 1*time.Second)
	defer srv.Close()

	c := New(srv.URL, "agent-1", "secret", "task-1")

	if _, err := c.Token(context.Background()); err != nil {
		t.Fatalf("Token failed: %v", err)
	}
	if _, err := c.Token(context.Background()); err != nil {
		t.Fatalf("Token failed: %v", err)
	}
	if got := atomic.LoadInt32(tokenRequests); got < 2 {
		t.Errorf("should refresh on every call when TTL is below the refresh margin, observed %d requests", got)
	}
}

func TestClient_Do_AttachesBearerToken(t *testing.T) {
	srv, _ := newMockNexus(t, 5*time.Minute)
	defer srv.Close()

	c := New(srv.URL, "agent-1", "secret", "task-1")

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/protected", nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("Do failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestClient_HTTPClient_AttachesBearerTokenTransparently(t *testing.T) {
	srv, _ := newMockNexus(t, 5*time.Minute)
	defer srv.Close()

	c := New(srv.URL, "agent-1", "secret", "task-1")
	httpClient := c.HTTPClient()

	resp, err := httpClient.Get(srv.URL + "/v1/protected")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestClient_PropagatesServerErrorOnTokenRequestFailure(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/nexus/identity/token", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "authentication failed", http.StatusUnauthorized)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := New(srv.URL, "agent-1", "wrong-secret", "task-1")
	if _, err := c.Token(context.Background()); err == nil {
		t.Error("Token should propagate the server's error")
	}
}

func TestWithScopesAndTTL_AreSentToServer(t *testing.T) {
	var captured tokenRequest
	mux := http.NewServeMux()
	mux.HandleFunc("/nexus/identity/token", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&captured)
		resp := tokenResponse{Token: "tok", ExpiresAt: time.Now().Add(time.Minute).Unix()}
		_ = json.NewEncoder(w).Encode(resp)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := New(srv.URL, "agent-1", "secret", "task-1", WithScopes("llm:openai:invoke"), WithTTL(45*time.Second))
	if _, err := c.Token(context.Background()); err != nil {
		t.Fatalf("Token failed: %v", err)
	}

	if len(captured.Scopes) != 1 || captured.Scopes[0] != "llm:openai:invoke" {
		t.Errorf("wrong scopes sent: %+v", captured.Scopes)
	}
	if captured.TTLSeconds != 45 {
		t.Errorf("ttl_seconds = %d, want 45", captured.TTLSeconds)
	}
}
