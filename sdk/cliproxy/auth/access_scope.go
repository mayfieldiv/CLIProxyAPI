package auth

import (
	"strings"
	"sync/atomic"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

var accessScopeEnforced atomic.Bool

// SetAccessScopeEnforced makes a request without an access scope unable to select any
// credential, so a path that lost its scope fails closed. Scoped requests are confined to
// their own credentials whether or not this is set.
//
// Home dispatch does not consult this rule; scoped keys are unsupported in Home mode.
func SetAccessScopeEnforced(enforced bool) {
	accessScopeEnforced.Store(enforced)
}

func accessScopeAllows(requestScope string, auth *Auth) bool {
	if requestScope != "" {
		return authMetadataString(auth, cliproxyexecutor.AccessScopeMetadataKey) == requestScope
	}
	return !accessScopeEnforced.Load()
}

func accessScopeFromMetadata(metadata map[string]any) string {
	scope, _ := metadata[cliproxyexecutor.AccessScopeMetadataKey].(string)
	return strings.TrimSpace(scope)
}
