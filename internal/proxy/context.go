// context.go propagates parser.RequestMeta through the context.Context
// of the internal request sent to the upstream, so that ModifyResponse
// (which only receives *http.Response, with no direct access to
// buildHandler's local variables) can retrieve the current request's
// metadata to call SpendRecorder with the correct agent/task
// information.
package proxy

import (
	"context"

	"nexus-gateway/internal/parser"
)

type contextKey int

const requestMetaContextKey contextKey = iota

func withRequestMeta(ctx context.Context, meta *parser.RequestMeta) context.Context {
	return context.WithValue(ctx, requestMetaContextKey, meta)
}

func requestMetaFromContext(ctx context.Context) (*parser.RequestMeta, bool) {
	meta, ok := ctx.Value(requestMetaContextKey).(*parser.RequestMeta)
	return meta, ok
}
