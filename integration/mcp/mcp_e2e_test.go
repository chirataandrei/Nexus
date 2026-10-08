// Package mcp_e2e runs the real gateway binary between the official MCP Go
// SDK's client and server. It lives in its own module (the SDK needs a
// newer Go than the gateway, and the gateway has no dependencies), so it
// is not part of `go test ./...` at the repository root:
//
//	cd integration/mcp && GOWORK=off go test -count=1 ./...
//
// What it proves: the message shapes the gateway recognises are the ones a
// real MCP client and server exchange — initialize, notifications, tools/list,
// tools/call over the Streamable HTTP transport (including SSE responses) —
// and per-tool scopes are enforced on real traffic.
package mcp_e2e

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type addArgs struct {
	A int `json:"a"`
	B int `json:"b"`
}
type addResult struct {
	Sum int `json:"sum"`
}
type noArgs struct{}

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func goBuild(t *testing.T, root, out, pkg string) {
	t.Helper()
	cmd := exec.Command("go", "build", "-o", out, pkg)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOWORK=off")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build %s: %v\n%s", pkg, err, b)
	}
}

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

// bearer injects the agent's token on every request the MCP client makes.
type bearer struct{ token string }

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	if b.token != "" {
		r.Header.Set("Authorization", "Bearer "+b.token)
	}
	return http.DefaultTransport.RoundTrip(r)
}

func TestRealMCPClientAndServerThroughGateway(t *testing.T) {
	root := repoRoot(t)
	dir := t.TempDir()

	// --- a real MCP server with a harmless and a dangerous tool -----------
	var dangerCalls atomic.Int32
	srv := mcp.NewServer(&mcp.Implementation{Name: "calc", Version: "1.0.0"}, nil)
	mcp.AddTool(srv, &mcp.Tool{Name: "add", Description: "add two integers"},
		func(_ context.Context, _ *mcp.CallToolRequest, in addArgs) (*mcp.CallToolResult, addResult, error) {
			return nil, addResult{Sum: in.A + in.B}, nil
		})
	mcp.AddTool(srv, &mcp.Tool{Name: "wipe_database", Description: "dangerous"},
		func(_ context.Context, _ *mcp.CallToolRequest, _ noArgs) (*mcp.CallToolResult, any, error) {
			dangerCalls.Add(1)
			return nil, nil, nil
		})
	upstream := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, nil))
	defer upstream.Close()

	// --- the real gateway binary, configured with per-tool scopes ---------
	goBuild(t, root, filepath.Join(dir, "gw"), "./cmd/nexus-gateway")
	goBuild(t, root, filepath.Join(dir, "ctl"), "./cmd/nexus-agentctl")

	adminOut, err := exec.Command(filepath.Join(dir, "ctl"), "-gen-admin-token").Output()
	if err != nil {
		t.Fatal(err)
	}
	var adminHash string
	for _, l := range strings.Split(string(adminOut), "\n") {
		if strings.Contains(l, "admin_token_sha256") {
			adminHash = strings.Split(l, `"`)[3]
		}
	}
	if len(adminHash) != 64 {
		t.Fatalf("could not parse admin hash from %q", adminOut)
	}
	entry, err := exec.Command(filepath.Join(dir, "ctl"), "-agent-id", "mcp-agent", "-secret", "s3cret-for-test",
		"-scopes", "tools:calc:invoke,tools:calc:add").Output()
	if err != nil {
		t.Fatal(err)
	}
	entryJSON := entry[bytes.IndexByte(entry, '\n')+1:] // drop the comment line
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	agents := write("agents.json", fmt.Sprintf(`{"default_max_ttl_seconds":300,"agents":[%s]}`, entryJSON))
	finops := write("finops.json", `{"default_daily_budget_usd":10,"default_max_cost_per_request_usd":0.01}`)
	gwAddr := freeAddr(t)
	cfg := write("config.json", fmt.Sprintf(`{
  "listen_addr": %q, "max_body_bytes": 1048576, "trust_domain": "e2e.trust",
  "agents_file": %q, "identity_key_file": %q, "admin_token_sha256": %q,
  "finops_policies_file": %q,
  "compliance_ledger_file": %q, "compliance_retention_months": 6,
  "upstreams": [{
    "name": "calc", "path_prefix": "/mcp", "target_url": %q, "strip_prefix": false,
    "required_scope": "tools:calc:invoke",
    "tool_scopes": {"add": "tools:calc:add", "wipe_database": "tools:calc:wipe"}
  }]}`, gwAddr, agents, filepath.Join(dir, "id.key.json"), adminHash, finops,
		filepath.Join(dir, "ledger.jsonl"), upstream.URL))

	gw := exec.Command(filepath.Join(dir, "gw"), "-config", cfg)
	var gwLog bytes.Buffer
	gw.Stdout, gw.Stderr = &gwLog, &gwLog
	if err := gw.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = gw.Process.Signal(os.Interrupt)
		_ = gw.Wait()
		if t.Failed() {
			t.Logf("gateway log:\n%s", gwLog.String())
		}
	}()
	base := "http://" + gwAddr
	waitFor(t, base+"/nexus/compliance/verify")

	// --- the agent gets a token, then speaks real MCP through the gateway --
	tokenReq := `{"agent_id":"mcp-agent","secret":"s3cret-for-test","task_id":"e2e"}`
	resp, err := http.Post(base+"/nexus/identity/token", "application/json", strings.NewReader(tokenReq))
	if err != nil {
		t.Fatal(err)
	}
	var tok struct {
		Token string `json:"token"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&tok)
	resp.Body.Close()
	if tok.Token == "" {
		t.Fatalf("no token issued (status %d)", resp.StatusCode)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	connect := func(token string) (*mcp.ClientSession, error) {
		c := mcp.NewClient(&mcp.Implementation{Name: "e2e-client", Version: "1.0.0"}, nil)
		return c.Connect(ctx, &mcp.StreamableClientTransport{
			Endpoint:   base + "/mcp",
			HTTPClient: &http.Client{Transport: bearer{token}},
		}, nil)
	}

	t.Run("no token: the MCP handshake is refused", func(t *testing.T) {
		if s, err := connect(""); err == nil {
			s.Close()
			t.Fatal("an MCP client without identity completed the handshake")
		}
	})

	session, err := connect(tok.Token)
	if err != nil {
		t.Fatalf("initialize through the gateway failed: %v\n%s", err, gwLog.String())
	}
	defer session.Close()

	t.Run("tools/list passes through", func(t *testing.T) {
		res, err := session.ListTools(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		names := map[string]bool{}
		for _, tl := range res.Tools {
			names[tl.Name] = true
		}
		if !names["add"] || !names["wipe_database"] {
			t.Fatalf("tools = %v", names)
		}
	})

	t.Run("tools/call within the agent's scopes works", func(t *testing.T) {
		res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "add", Arguments: map[string]any{"a": 2, "b": 3}})
		if err != nil || res.IsError {
			t.Fatalf("add failed: %v %+v", err, res)
		}
		b, _ := json.Marshal(res.StructuredContent)
		if !strings.Contains(string(b), `"sum":5`) {
			t.Fatalf("unexpected result %s", b)
		}
	})

	t.Run("tools/call outside the agent's scopes is blocked before the server", func(t *testing.T) {
		_, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "wipe_database", Arguments: map[string]any{}})
		if err == nil {
			t.Fatal("the dangerous tool was callable without its scope")
		}
		if n := dangerCalls.Load(); n != 0 {
			t.Fatalf("the MCP server executed wipe_database %d time(s)", n)
		}
	})

	t.Run("the ledger names the exact tools and verifies", func(t *testing.T) {
		raw, err := os.ReadFile(filepath.Join(dir, "ledger.jsonl"))
		if err != nil {
			t.Fatal(err)
		}
		var sawAdd, sawWipeRejected bool
		sc := bufio.NewScanner(bytes.NewReader(raw))
		sc.Buffer(make([]byte, 0, 1<<20), 1<<24)
		for sc.Scan() {
			var r struct{ Event, Tool, Decision string }
			if json.Unmarshal(sc.Bytes(), &r) != nil {
				continue
			}
			if r.Tool == "add" && r.Event == "request_received" {
				sawAdd = true
			}
			if r.Tool == "wipe_database" && r.Event == "request_rejected" {
				sawWipeRejected = true
			}
		}
		if !sawAdd || !sawWipeRejected {
			t.Fatalf("ledger missing records: add=%v wipe_rejected=%v", sawAdd, sawWipeRejected)
		}
		vr, err := http.Get(base + "/nexus/compliance/verify")
		if err != nil {
			t.Fatal(err)
		}
		defer vr.Body.Close()
		body, _ := io.ReadAll(vr.Body)
		if vr.StatusCode != 200 {
			t.Fatalf("verify = %d %s", vr.StatusCode, body)
		}
	})
}

func waitFor(t *testing.T, url string) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if r, err := http.Get(url); err == nil {
			r.Body.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("gateway did not come up at %s", url)
}
