package auth

import (
	"context"
	"net/http"
	"sync"
	"testing"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

const (
	accessScopeTestModel = "access-scope-test-model"
	teamACredential      = "scope-test-team-a"
	teamBCredential      = "scope-test-team-b"
	unscopedCredential   = "scope-test-unscoped"
)

// recordingScopeExecutor records which credentials reach upstream. Every call fails with
// a 429 when failAll is set, which is what drives the manager toward failover.
type recordingScopeExecutor struct {
	schedulerTestExecutor
	failAll bool

	mu   sync.Mutex
	used []string
}

type accessScopeTestError struct{}

func (accessScopeTestError) Error() string   { return "rate limited" }
func (accessScopeTestError) StatusCode() int { return http.StatusTooManyRequests }

func (e *recordingScopeExecutor) record(auth *Auth) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.used = append(e.used, auth.ID)
	if e.failAll {
		return accessScopeTestError{}
	}
	return nil
}

func (e *recordingScopeExecutor) credentialsUsed() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.used...)
}

func (e *recordingScopeExecutor) Execute(_ context.Context, auth *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, e.record(auth)
}

func (e *recordingScopeExecutor) CountTokens(_ context.Context, auth *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, e.record(auth)
}

func (e *recordingScopeExecutor) ExecuteStream(_ context.Context, auth *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	if err := e.record(auth); err != nil {
		return nil, err
	}
	chunks := make(chan cliproxyexecutor.StreamChunk)
	close(chunks)
	return &cliproxyexecutor.StreamResult{Chunks: chunks}, nil
}

// enforceAccessScopeForTest must only be used by sequential tests. Go never runs them
// alongside the package's parallel tests, which rely on enforcement being off.
func enforceAccessScopeForTest(t *testing.T) {
	t.Helper()
	SetAccessScopeEnforced(true)
	t.Cleanup(func() { SetAccessScopeEnforced(false) })
}

func newAccessScopeManager(t *testing.T, selector Selector, executor ProviderExecutor) *Manager {
	t.Helper()
	registerSchedulerModels(t, "codex", accessScopeTestModel, teamACredential, teamBCredential, unscopedCredential)
	manager := NewManager(nil, selector, nil)
	manager.executors["codex"] = executor
	for id, scope := range map[string]string{teamACredential: "team-a", teamBCredential: "team-b", unscopedCredential: ""} {
		metadata := map[string]any{}
		if scope != "" {
			metadata[cliproxyexecutor.AccessScopeMetadataKey] = scope
		}
		if _, errRegister := manager.Register(context.Background(), &Auth{ID: id, Provider: "codex", Metadata: metadata}); errRegister != nil {
			t.Fatalf("Register(%s) error = %v", id, errRegister)
		}
	}
	return manager
}

func accessScopeOptions(scope string) cliproxyexecutor.Options {
	if scope == "" {
		return cliproxyexecutor.Options{}
	}
	return cliproxyexecutor.Options{Metadata: map[string]any{cliproxyexecutor.AccessScopeMetadataKey: scope}}
}

func TestAccessScopeConfinesEverySelectionPath(t *testing.T) {
	enforceAccessScopeForTest(t)
	manager := newAccessScopeManager(t, &RoundRobinSelector{}, schedulerTestExecutor{})

	picks := map[string]func(cliproxyexecutor.Options, map[string]struct{}) (*Auth, error){
		"pickNext": func(opts cliproxyexecutor.Options, tried map[string]struct{}) (*Auth, error) {
			auth, _, err := manager.pickNext(context.Background(), "codex", accessScopeTestModel, opts, tried)
			return auth, err
		},
		"pickNextLegacy": func(opts cliproxyexecutor.Options, tried map[string]struct{}) (*Auth, error) {
			auth, _, err := manager.pickNextLegacy(context.Background(), "codex", accessScopeTestModel, opts, tried)
			return auth, err
		},
		"pickNextMixed": func(opts cliproxyexecutor.Options, tried map[string]struct{}) (*Auth, error) {
			auth, _, _, err := manager.pickNextMixed(context.Background(), []string{"codex"}, accessScopeTestModel, opts, tried)
			return auth, err
		},
		"pickNextMixedLegacy": func(opts cliproxyexecutor.Options, tried map[string]struct{}) (*Auth, error) {
			auth, _, _, err := manager.pickNextMixedLegacy(context.Background(), []string{"codex"}, accessScopeTestModel, opts, tried)
			return auth, err
		},
	}
	for name, pick := range picks {
		t.Run(name, func(t *testing.T) {
			for scope, want := range map[string]string{"team-a": teamACredential, "team-b": teamBCredential} {
				for attempt := 0; attempt < 4; attempt++ {
					got, errPick := pick(accessScopeOptions(scope), map[string]struct{}{})
					if errPick != nil {
						t.Fatalf("scope %q: unexpected error %v", scope, errPick)
					}
					if got.ID != want {
						t.Fatalf("scope %q selected %q, want %q", scope, got.ID, want)
					}
				}
			}

			for _, scope := range []string{"", "team-unknown"} {
				if got, errPick := pick(accessScopeOptions(scope), map[string]struct{}{}); errPick == nil {
					t.Fatalf("scope %q selected %q, want an error", scope, got.ID)
				}
			}

			exhausted := map[string]struct{}{teamACredential: {}}
			if got, errPick := pick(accessScopeOptions("team-a"), exhausted); errPick == nil {
				t.Fatalf("scope team-a failed over to %q, want an error", got.ID)
			}
		})
	}
}

func TestAccessScopeNotEnforcedKeepsUpstreamSelection(t *testing.T) {
	manager := newAccessScopeManager(t, &RoundRobinSelector{}, schedulerTestExecutor{})
	seen := make(map[string]bool)
	for attempt := 0; attempt < 3; attempt++ {
		got, _, _, errPick := manager.pickNextMixed(context.Background(), []string{"codex"}, accessScopeTestModel, cliproxyexecutor.Options{}, map[string]struct{}{})
		if errPick != nil {
			t.Fatalf("pickNextMixed() error = %v", errPick)
		}
		seen[got.ID] = true
	}
	if len(seen) != 3 {
		t.Fatalf("selected %v, want all three credentials", seen)
	}
}

func TestAccessScopeFailoverStaysInsideScope(t *testing.T) {
	enforceAccessScopeForTest(t)
	request := cliproxyexecutor.Request{Model: accessScopeTestModel}
	calls := map[string]func(*Manager, cliproxyexecutor.Options) error{
		"Execute": func(manager *Manager, opts cliproxyexecutor.Options) error {
			_, err := manager.Execute(context.Background(), []string{"codex"}, request, opts)
			return err
		},
		"ExecuteCount": func(manager *Manager, opts cliproxyexecutor.Options) error {
			_, err := manager.ExecuteCount(context.Background(), []string{"codex"}, request, opts)
			return err
		},
		"ExecuteStream": func(manager *Manager, opts cliproxyexecutor.Options) error {
			_, err := manager.ExecuteStream(context.Background(), []string{"codex"}, request, opts)
			return err
		},
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			executor := &recordingScopeExecutor{failAll: true}
			manager := newAccessScopeManager(t, &RoundRobinSelector{}, executor)
			if errCall := call(manager, accessScopeOptions("team-a")); errCall == nil {
				t.Fatal("call succeeded, want the rate limit error")
			}
			used := executor.credentialsUsed()
			if len(used) == 0 {
				t.Fatal("no credential reached upstream")
			}
			for _, id := range used {
				if id != teamACredential {
					t.Fatalf("credential %q reached upstream for scope team-a (all: %v)", id, used)
				}
			}
		})
	}
}

func TestAccessScopeOverridesSessionAffinityAndPins(t *testing.T) {
	enforceAccessScopeForTest(t)
	selector := NewSessionAffinitySelector(&RoundRobinSelector{})
	t.Cleanup(selector.Stop)
	manager := newAccessScopeManager(t, selector, schedulerTestExecutor{})

	withSession := func(scope string) cliproxyexecutor.Options {
		opts := accessScopeOptions(scope)
		opts.Headers = http.Header{"X-Session-Id": {"same-session-from-two-keys"}}
		return opts
	}
	for _, step := range []struct{ scope, want string }{
		{"team-a", teamACredential},
		{"team-b", teamBCredential},
		{"team-a", teamACredential},
	} {
		got, _, _, errPick := manager.pickNextMixed(context.Background(), []string{"codex"}, accessScopeTestModel, withSession(step.scope), map[string]struct{}{})
		if errPick != nil {
			t.Fatalf("scope %q: pickNextMixed() error = %v", step.scope, errPick)
		}
		if got.ID != step.want {
			t.Fatalf("scope %q selected %q, want %q", step.scope, got.ID, step.want)
		}
	}

	pinned := accessScopeOptions("team-a")
	pinned.Metadata[cliproxyexecutor.PinnedAuthMetadataKey] = teamBCredential
	if got, _, _, errPick := manager.pickNextMixed(context.Background(), []string{"codex"}, accessScopeTestModel, pinned, map[string]struct{}{}); errPick == nil {
		t.Fatalf("scope team-a pinned to team-b selected %q, want an error", got.ID)
	}
}
