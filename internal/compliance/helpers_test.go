package compliance

import (
	"net/http"
	"net/http/httptest"
	"strings"
)

func httptestRequest(body string) *http.Request {
	return httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(body))
}

func newRecorder() *httptest.ResponseRecorder { return httptest.NewRecorder() }
