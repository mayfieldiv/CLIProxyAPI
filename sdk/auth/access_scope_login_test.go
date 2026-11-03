package auth

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	claudeauth "github.com/router-for-me/CLIProxyAPI/v8/internal/auth/claude"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

type scopeLoginAuthenticator struct{}

func (scopeLoginAuthenticator) Provider() string            { return "claude" }
func (scopeLoginAuthenticator) RefreshLead() *time.Duration { return nil }
func (scopeLoginAuthenticator) Login(context.Context, *config.Config, *LoginOptions) (*coreauth.Auth, error) {
	return &coreauth.Auth{
		ID:       "claude-scope.json",
		Provider: "claude",
		FileName: "claude-scope.json",
		Storage:  &claudeauth.ClaudeTokenStorage{Email: "scope@example.com", AccessToken: "token"},
		Metadata: map[string]any{"email": "scope@example.com"},
	}, nil
}

func savedAccessScope(t *testing.T, path string) any {
	t.Helper()
	raw, errRead := os.ReadFile(path)
	if errRead != nil {
		t.Fatalf("read saved credential: %v", errRead)
	}
	var saved map[string]any
	if errParse := json.Unmarshal(raw, &saved); errParse != nil {
		t.Fatalf("parse saved credential: %v", errParse)
	}
	return saved[cliproxyexecutor.AccessScopeMetadataKey]
}

func TestLoginPersistsAccessScope(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{}
	cfg.AuthDir = dir
	manager := NewManager(NewFileTokenStore(), scopeLoginAuthenticator{})
	path := filepath.Join(dir, "claude-scope.json")

	if _, _, errLogin := manager.Login(context.Background(), "claude", cfg, &LoginOptions{}); errLogin != nil {
		t.Fatalf("unscoped Login() error = %v", errLogin)
	}
	if got := savedAccessScope(t, path); got != nil {
		t.Fatalf("access_scope = %v after an unscoped login, want none", got)
	}

	if _, _, errLogin := manager.Login(context.Background(), "claude", cfg, &LoginOptions{AccessScope: " team-a "}); errLogin != nil {
		t.Fatalf("scoped Login() error = %v", errLogin)
	}
	if got := savedAccessScope(t, path); got != "team-a" {
		t.Fatalf("access_scope = %v, want team-a", got)
	}

	if _, _, errLogin := manager.Login(context.Background(), "claude", cfg, &LoginOptions{}); errLogin != nil {
		t.Fatalf("re-login error = %v", errLogin)
	}
	if got := savedAccessScope(t, path); got != "team-a" {
		t.Fatalf("access_scope = %v after re-login without a flag, want team-a", got)
	}
}
