package parser

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

// FuzzParse feeds arbitrary bodies to Parse. Invariants: it never panics,
// it returns the body byte-for-byte (it is forwarded to the upstream), and
// a batch is never reported together with a tool name (a batch must not be
// authorized as if it were a single call).
func FuzzParse(f *testing.F) {
	for _, seed := range []string{
		``, `{}`, `[]`, `null`, `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"x"}}`,
		`[{"jsonrpc":"2.0","method":"tools/call","params":{"name":"delete_email"}}]`,
		`  [ {"jsonrpc":"2.0"} ]`, `{"jsonrpc":"2.0","method":"tools/call","params":"str"}`,
		"\xff\xfe", `{"jsonrpc":"2.0","method":"tools/call","params":{"name":{"a":1}}}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
		meta, got, err := Parse(req)
		if err != nil {
			t.Fatalf("Parse error: %v", err)
		}
		if !bytes.Equal(got, body) {
			t.Fatal("Parse must return the body unchanged")
		}
		if meta.IsBatch && meta.MCPTool != "" {
			t.Fatal("a batch must never carry an MCP tool name")
		}
	})
}
