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
