package idx

import "context"

type deviceContextKey string

const (
	xForwardedFor          deviceContextKey = "X-Forwarded-For"
	userAgent              deviceContextKey = "User-Agent"
	xOktaUserAgentExtended deviceContextKey = "X-Okta-User-Agent-Extended"
	xDeviceToken           deviceContextKey = "X-Device-Token" // nolint:gosec
)

var deviceContextKeys = []deviceContextKey{xForwardedFor, userAgent, xOktaUserAgentExtended, xDeviceToken}

func WithXForwardedFor(ctx context.Context, value string) context.Context {
	return context.WithValue(ctx, xForwardedFor, value)
}

func WithUserAgent(ctx context.Context, value string) context.Context {
	return context.WithValue(ctx, userAgent, value)
}

func WithXOktaUserAgentExtended(ctx context.Context, value string) context.Context {
	return context.WithValue(ctx, xOktaUserAgentExtended, value)
}

func WithXDeviceToken(ctx context.Context, value string) context.Context {
	return context.WithValue(ctx, xDeviceToken, value)
}
