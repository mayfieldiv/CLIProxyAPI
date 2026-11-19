package auth

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

const daybreakUnavailableBody = `{"detail":"Daybreak isn't available for this model. Turn off Daybreak or choose another model."}`

func TestCodexAccessProgramRejection_ReturnsUpstreamErrorWithoutCooldown(t *testing.T) {
	previous := quotaCooldownDisabled.Load()
	quotaCooldownDisabled.Store(false)
	t.Cleanup(func() { quotaCooldownDisabled.Store(previous) })

	testCases := []struct {
		name   string
		invoke func(*Manager, cliproxyexecutor.Request) error
	}{
		{
			name: "execute",
			invoke: func(m *Manager, request cliproxyexecutor.Request) error {
				_, errExecute := m.Execute(context.Background(), []string{"codex"}, request, cliproxyexecutor.Options{})
				return errExecute
			},
		},
		{
			name: "execute_stream",
			invoke: func(m *Manager, request cliproxyexecutor.Request) error {
				result, errExecute := m.ExecuteStream(context.Background(), []string{"codex"}, request, cliproxyexecutor.Options{})
				if errExecute != nil {
					return errExecute
				}
				for chunk := range result.Chunks {
					if chunk.Err != nil {
						return chunk.Err
					}
				}
				return nil
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			model := "gpt-6.2-sol"
			first := &Auth{ID: "aa-codex-daybreak-" + tc.name, Provider: "codex"}
			second := &Auth{ID: "bb-codex-daybreak-" + tc.name, Provider: "codex"}
			rejection := &statusBearingError{status: http.StatusNotFound, msg: daybreakUnavailableBody}
			executor := &authFallbackExecutor{
				id:                "codex",
				executeErrors:     map[string]error{first.ID: rejection, second.ID: rejection},
				streamFirstErrors: map[string]error{first.ID: rejection, second.ID: rejection},
			}

			m := NewManager(nil, nil, nil)
			m.RegisterExecutor(executor)
			reg := registry.GetGlobalRegistry()
			reg.RegisterClient(first.ID, "codex", []*registry.ModelInfo{{ID: model}})
			reg.RegisterClient(second.ID, "codex", []*registry.ModelInfo{{ID: model}})
			t.Cleanup(func() {
				reg.UnregisterClient(first.ID)
				reg.UnregisterClient(second.ID)
			})
			for _, auth := range []*Auth{first, second} {
				if _, errRegister := m.Register(context.Background(), auth); errRegister != nil {
					t.Fatalf("register %s: %v", auth.ID, errRegister)
				}
			}

			request := cliproxyexecutor.Request{Model: model}
			errInvoke := tc.invoke(m, request)
			if errInvoke == nil {
				t.Fatal("expected the Daybreak rejection to reach the caller")
			}
			var statusErr interface{ StatusCode() int }
			if !errors.As(errInvoke, &statusErr) || statusErr.StatusCode() != http.StatusNotFound {
				t.Fatalf("error = %v, want upstream status %d", errInvoke, http.StatusNotFound)
			}
			if errInvoke.Error() != daybreakUnavailableBody {
				t.Fatalf("error body = %q, want upstream body %q", errInvoke.Error(), daybreakUnavailableBody)
			}

			calls := executor.ExecuteCalls()
			if tc.name == "execute_stream" {
				calls = executor.StreamCalls()
			}
			if len(calls) != 1 {
				t.Fatalf("upstream calls = %v, want one call without credential rotation", calls)
			}

			for _, auth := range []*Auth{first, second} {
				updated, ok := m.GetByID(auth.ID)
				if !ok || updated == nil {
					t.Fatalf("auth %s missing", auth.ID)
				}
				if updated.Unavailable || !updated.NextRetryAfter.IsZero() {
					t.Fatalf("auth %s cooled down: unavailable=%t next=%v", auth.ID, updated.Unavailable, updated.NextRetryAfter)
				}
				if state := updated.ModelStates[model]; state != nil && (state.Unavailable || !state.NextRetryAfter.IsZero()) {
					t.Fatalf("auth %s model %s cooled down: %#v", auth.ID, model, state)
				}
			}

			executor.mu.Lock()
			executor.executeErrors = nil
			executor.streamFirstErrors = nil
			executor.mu.Unlock()
			if errInvoke := tc.invoke(m, request); errInvoke != nil {
				t.Fatalf("request without the access program failed after the rejection: %v", errInvoke)
			}
		})
	}
}

// syncStreamRejectExecutor fails ExecuteStream before any stream exists, the
// way a real HTTP 404 from the Codex upstream does.
type syncStreamRejectExecutor struct {
	*authFallbackExecutor
	err   error
	calls []string
}

func (e *syncStreamRejectExecutor) ExecuteStream(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	e.calls = append(e.calls, auth.ID)
	if e.err != nil {
		return nil, e.err
	}
	return e.authFallbackExecutor.ExecuteStream(ctx, auth, req, opts)
}

func TestCodexAccessProgramRejection_SynchronousStreamErrorSkipsCooldown(t *testing.T) {
	previous := quotaCooldownDisabled.Load()
	quotaCooldownDisabled.Store(false)
	t.Cleanup(func() { quotaCooldownDisabled.Store(previous) })

	model := "gpt-6.2-sol"
	first := &Auth{ID: "aa-codex-daybreak-sync", Provider: "codex"}
	second := &Auth{ID: "bb-codex-daybreak-sync", Provider: "codex"}
	executor := &syncStreamRejectExecutor{
		authFallbackExecutor: &authFallbackExecutor{id: "codex"},
		err:                  &statusBearingError{status: http.StatusNotFound, msg: daybreakUnavailableBody},
	}

	m := NewManager(nil, nil, nil)
	m.RegisterExecutor(executor)
	reg := registry.GetGlobalRegistry()
	reg.RegisterClient(first.ID, "codex", []*registry.ModelInfo{{ID: model}})
	reg.RegisterClient(second.ID, "codex", []*registry.ModelInfo{{ID: model}})
	t.Cleanup(func() {
		reg.UnregisterClient(first.ID)
		reg.UnregisterClient(second.ID)
	})
	for _, auth := range []*Auth{first, second} {
		if _, errRegister := m.Register(context.Background(), auth); errRegister != nil {
			t.Fatalf("register %s: %v", auth.ID, errRegister)
		}
	}

	request := cliproxyexecutor.Request{Model: model}
	_, errStream := m.ExecuteStream(context.Background(), []string{"codex"}, request, cliproxyexecutor.Options{})
	var statusErr interface{ StatusCode() int }
	if !errors.As(errStream, &statusErr) || statusErr.StatusCode() != http.StatusNotFound || errStream.Error() != daybreakUnavailableBody {
		t.Fatalf("error = %v, want upstream 404 with its body", errStream)
	}
	if len(executor.calls) != 1 {
		t.Fatalf("upstream calls = %v, want one call without credential rotation", executor.calls)
	}
	for _, auth := range []*Auth{first, second} {
		updated, ok := m.GetByID(auth.ID)
		if !ok || updated == nil {
			t.Fatalf("auth %s missing", auth.ID)
		}
		if state := updated.ModelStates[model]; updated.Unavailable || (state != nil && (state.Unavailable || !state.NextRetryAfter.IsZero())) {
			t.Fatalf("auth %s cooled down after the rejection", auth.ID)
		}
	}
}
