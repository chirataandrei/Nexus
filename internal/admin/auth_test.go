package admin

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequire(t *testing.T) {
	tok, _ := GenerateToken()
	h := Require(HashToken(tok), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	for name, tc := range map[string]struct {
		header string
		want   int
	}{
		"valid":        {"Bearer " + tok, 204},
		"missing":      {"", 401},
		"wrong":        {"Bearer nope", 401},
		"no bearer":    {tok, 401},
		"empty bearer": {"Bearer ", 401},
	} {
		req := httptest.NewRequest(http.MethodPost, "/nexus/control/suspend", nil)
		if tc.header != "" {
			req.Header.Set("Authorization", tc.header)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Errorf("%s: status %d, want %d", name, rec.Code, tc.want)
		}
	}
}
