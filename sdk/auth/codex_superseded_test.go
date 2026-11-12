package auth

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	codexauth "github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func writeCodexCredential(t *testing.T, dir, name, accountID, scope string) string {
	t.Helper()
	credential := map[string]any{
		"type":          "codex",
		"email":         "user@example.com",
		"account_id":    accountID,
		"refresh_token": "old-token",
	}
	if scope != "" {
		credential["access_scope"] = scope
	}
	raw, errMarshal := json.Marshal(credential)
	if errMarshal != nil {
		t.Fatalf("marshal %s: %v", name, errMarshal)
	}
	path := filepath.Join(dir, name)
	if errWrite := os.WriteFile(path, raw, 0o600); errWrite != nil {
		t.Fatalf("write %s: %v", name, errWrite)
	}
	return path
}

func TestManagerLogin_CodexPlanChangeReplacesPreviousLogin(t *testing.T) {
	authDir := t.TempDir()
	previousPlan := writeCodexCredential(t, authDir, "codex-3a43d211-user@example.com-pro.json", "account-1", "personal")
	otherScope := writeCodexCredential(t, authDir, "codex-3a43d211-user@example.com-plus.json", "account-1", "team")
	otherAccount := writeCodexCredential(t, authDir, "codex-9b1c0e22-user@example.com-team.json", "account-2", "personal")

	targetFileName := codexauth.CredentialFileName("user@example.com", "prolite", "3a43d211", true)
	newRecord := &coreauth.Auth{
		ID:       targetFileName,
		FileName: targetFileName,
		Provider: "codex",
		Storage: &codexauth.CodexTokenStorage{
			Type:         "codex",
			Email:        "user@example.com",
			AccountID:    "account-1",
			RefreshToken: "new-token",
			PlanType:     "prolite",
		},
		Metadata: map[string]any{"email": "user@example.com", "plan_type": "prolite"},
	}

	store := NewFileTokenStore()
	store.SetBaseDir(authDir)
	mgr := NewManager(store, &dummyAuthenticator{provider: "codex", record: newRecord})
	_, savedPath, errLogin := mgr.Login(context.Background(), "codex", &config.Config{AuthDir: authDir}, &LoginOptions{AccessScope: "personal"})
	if errLogin != nil {
		t.Fatalf("Login error: %v", errLogin)
	}
	if savedPath != filepath.Join(authDir, targetFileName) {
		t.Fatalf("savedPath = %s, want %s", savedPath, targetFileName)
	}
	if _, errStat := os.Stat(previousPlan); !os.IsNotExist(errStat) {
		t.Fatalf("previous plan's login still exists or stat failed: %v", errStat)
	}
	for _, kept := range []string{otherScope, otherAccount} {
		if _, errStat := os.Stat(kept); errStat != nil {
			t.Fatalf("%s was removed: %v", filepath.Base(kept), errStat)
		}
	}
}
