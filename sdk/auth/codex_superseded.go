package auth

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	codexauth "github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// findSupersededCodexCredentials returns the other saved logins for the same ChatGPT account
// and email as target. Codex file names include the plan, so a login after a plan change gets
// a new file and the old one, whose refresh token the new login has revoked, would otherwise
// stay in rotation. A predecessor with a different access scope is kept, because removing it
// would cut off that scope's clients.
func findSupersededCodexCredentials(ctx context.Context, store coreauth.Store, target *coreauth.Auth, accessScope string) ([]*coreauth.Auth, error) {
	if store == nil || target == nil || !strings.EqualFold(strings.TrimSpace(target.Provider), "codex") {
		return nil, nil
	}
	email := metadataStringValue(target.Metadata, "email")
	accountID := metadataStringValue(target.Metadata, "account_id")
	if storage, ok := target.Storage.(*codexauth.CodexTokenStorage); ok && storage != nil {
		email = strings.TrimSpace(storage.Email)
		accountID = strings.TrimSpace(storage.AccountID)
	}
	if email == "" || accountID == "" {
		return nil, nil
	}

	records, errList := store.List(ctx)
	if errList != nil {
		if errors.Is(errList, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("list Codex credentials for superseded logins: %w", errList)
	}

	targetName := credentialBaseName(target)
	var superseded []*coreauth.Auth
	for _, candidate := range records {
		if candidate == nil || !strings.EqualFold(strings.TrimSpace(candidate.Provider), "codex") {
			continue
		}
		if strings.EqualFold(credentialBaseName(candidate), targetName) {
			continue
		}
		if !strings.EqualFold(metadataStringValue(candidate.Metadata, "email"), email) ||
			metadataStringValue(candidate.Metadata, "account_id") != accountID {
			continue
		}
		if accessScope != "" && metadataStringValue(candidate.Metadata, cliproxyexecutor.AccessScopeMetadataKey) != accessScope {
			continue
		}
		superseded = append(superseded, candidate)
	}
	return superseded, nil
}

func credentialBaseName(record *coreauth.Auth) string {
	name := strings.TrimSpace(record.FileName)
	if name == "" {
		name = strings.TrimSpace(record.ID)
	}
	return filepath.Base(name)
}
