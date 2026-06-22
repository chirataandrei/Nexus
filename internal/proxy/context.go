// context.go propagă parser.RequestMeta prin context.Context al cererii
// interne trimise upstream-ului, astfel încât ModifyResponse (care primește
// doar *http.Response, fără acces direct la variabilele locale din
// buildHandler) poate recupera metadatele cererii curente pentru a apela
// SpendRecorder cu informația corectă despre agent/sarcină.
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
