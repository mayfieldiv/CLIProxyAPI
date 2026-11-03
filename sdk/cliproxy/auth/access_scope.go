package auth

import (
	"strings"
	"sync/atomic"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

var accessScopeEnforced atomic.Bool

// SetAccessScopeEnforced turns on strict credential scoping for selection. While
// enforced, a credential is selectable only when the request's access scope and the
// credential's access_scope are both non-empty and equal, so a request that lost its
// scope and a login that was never classified both fail closed.
//
// Home dispatch does not consult this rule; scoped keys are unsupported in Home mode.
func SetAccessScopeEnforced(enforced bool) {
	accessScopeEnforced.Store(enforced)
}

func accessScopeAllows(requestScope string, auth *Auth) bool {
	if !accessScopeEnforced.Load() {
		return true
	}
	return requestScope != "" && authMetadataString(auth, cliproxyexecutor.AccessScopeMetadataKey) == requestScope
}

func accessScopeFromMetadata(metadata map[string]any) string {
	scope, _ := metadata[cliproxyexecutor.AccessScopeMetadataKey].(string)
	return strings.TrimSpace(scope)
}
