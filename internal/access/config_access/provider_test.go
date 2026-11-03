package configaccess

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	sdkaccess "github.com/router-for-me/CLIProxyAPI/v8/sdk/access"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
)

func registeredManager(t *testing.T, cfg *sdkconfig.SDKConfig) *sdkaccess.Manager {
	t.Helper()
	Register(cfg)
	t.Cleanup(func() { Register(nil) })
	manager := sdkaccess.NewManager()
	manager.SetProviders(sdkaccess.RegisteredProviders())
	return manager
}

func authenticate(manager *sdkaccess.Manager, key string) (*sdkaccess.Result, *sdkaccess.AuthError) {
	request := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	if key != "" {
		request.Header.Set("Authorization", "Bearer "+key)
	}
	return manager.Authenticate(context.Background(), request)
}

func TestScopedKeysAloneKeepAuthenticationRequired(t *testing.T) {
	manager := registeredManager(t, &sdkconfig.SDKConfig{
		ScopedAPIKeys: []sdkconfig.ScopedAPIKey{{Key: " key-a ", Scope: " team-a "}},
	})

	if _, errAuth := authenticate(manager, ""); errAuth == nil {
		t.Fatal("request without a key was authenticated")
	}
	if _, errAuth := authenticate(manager, "key-unknown"); errAuth == nil {
		t.Fatal("request with an unknown key was authenticated")
	}

	result, errAuth := authenticate(manager, "key-a")
	if errAuth != nil {
		t.Fatalf("Authenticate(key-a) error = %v", errAuth)
	}
	if got := result.Metadata[cliproxyexecutor.AccessScopeMetadataKey]; got != "team-a" {
		t.Fatalf("access scope = %q, want team-a", got)
	}
}

func TestUnscopedKeyCarriesNoScope(t *testing.T) {
	manager := registeredManager(t, &sdkconfig.SDKConfig{APIKeys: []string{"key-plain"}})

	result, errAuth := authenticate(manager, "key-plain")
	if errAuth != nil {
		t.Fatalf("Authenticate(key-plain) error = %v", errAuth)
	}
	if got, present := result.Metadata[cliproxyexecutor.AccessScopeMetadataKey]; present {
		t.Fatalf("access scope = %q, want none", got)
	}
}
