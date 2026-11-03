package api

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	proxyconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
)

type accessScopeRecordingExecutor struct {
	provider string

	mu   sync.Mutex
	used []string
}

func (e *accessScopeRecordingExecutor) record(credential *auth.Auth) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.used = append(e.used, credential.ID)
}

func (e *accessScopeRecordingExecutor) take() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	used := e.used
	e.used = nil
	return used
}

func (e *accessScopeRecordingExecutor) Identifier() string { return e.provider }

func (e *accessScopeRecordingExecutor) Execute(_ context.Context, credential *auth.Auth, _ coreexecutor.Request, _ coreexecutor.Options) (coreexecutor.Response, error) {
	e.record(credential)
	return coreexecutor.Response{Payload: []byte(`{}`)}, nil
}

func (e *accessScopeRecordingExecutor) ExecuteStream(_ context.Context, credential *auth.Auth, _ coreexecutor.Request, _ coreexecutor.Options) (*coreexecutor.StreamResult, error) {
	e.record(credential)
	chunks := make(chan coreexecutor.StreamChunk, 1)
	chunks <- coreexecutor.StreamChunk{Payload: []byte("data: {}\n\n")}
	close(chunks)
	return &coreexecutor.StreamResult{Chunks: chunks}, nil
}

func (e *accessScopeRecordingExecutor) Refresh(_ context.Context, credential *auth.Auth) (*auth.Auth, error) {
	return credential, nil
}

func (e *accessScopeRecordingExecutor) CountTokens(_ context.Context, credential *auth.Auth, _ coreexecutor.Request, _ coreexecutor.Options) (coreexecutor.Response, error) {
	e.record(credential)
	return coreexecutor.Response{Payload: []byte(`{"input_tokens":1}`)}, nil
}

func (e *accessScopeRecordingExecutor) PrepareRequest(*http.Request, *auth.Auth) error { return nil }

func (e *accessScopeRecordingExecutor) HttpRequest(_ context.Context, credential *auth.Auth, request *http.Request) (*http.Response, error) {
	e.record(credential)
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(strings.NewReader(`{"results":[]}`)),
		Request:    request,
	}, nil
}

type accessScopeFixture struct {
	server *Server
	claude *accessScopeRecordingExecutor
	codex  *accessScopeRecordingExecutor
}

const (
	accessScopeClaudeModel = "access-scope-claude-model"
	accessScopeCodexModel  = "access-scope-codex-model"
)

// newAccessScopeFixture holds two orgs with Claude and Codex credentials each, plus one
// credential of each provider that no login has classified.
func newAccessScopeFixture(t *testing.T) *accessScopeFixture {
	t.Helper()
	t.Cleanup(func() { auth.SetAccessScopeEnforced(false) })
	server := newTestServerWithConfig(t, &proxyconfig.Config{
		SDKConfig: sdkconfig.SDKConfig{ScopedAPIKeys: []sdkconfig.ScopedAPIKey{
			{Key: "key-a", Scope: "team-a"},
			{Key: "key-b", Scope: "team-b"},
			{Key: "key-empty", Scope: "team-without-credentials"},
		}},
	})
	fixture := &accessScopeFixture{
		server: server,
		claude: &accessScopeRecordingExecutor{provider: "claude"},
		codex:  &accessScopeRecordingExecutor{provider: "codex"},
	}
	server.handlers.AuthManager.RegisterExecutor(fixture.claude)
	server.handlers.AuthManager.RegisterExecutor(fixture.codex)
	for provider, model := range map[string]string{"claude": accessScopeClaudeModel, "codex": accessScopeCodexModel} {
		for _, scope := range []string{"team-a", "team-b", ""} {
			id := "access-scope-" + provider + "-" + scope
			metadata := map[string]any{"type": provider, "access_token": "token-" + id}
			if scope != "" {
				metadata[coreexecutor.AccessScopeMetadataKey] = scope
			}
			registry.GetGlobalRegistry().RegisterClient(id, provider, []*registry.ModelInfo{{ID: model}})
			t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
			credential := &auth.Auth{ID: id, Provider: provider, Status: auth.StatusActive, Metadata: metadata}
			if _, errRegister := server.handlers.AuthManager.Register(t.Context(), credential); errRegister != nil {
				t.Fatalf("register %s: %v", id, errRegister)
			}
		}
	}
	return fixture
}

func TestAccessScopeRoutesReachOnlyTheirOwnCredential(t *testing.T) {
	routes := []struct {
		name, path, body, provider string
	}{
		{"messages", "/v1/messages", `{"model":"` + accessScopeClaudeModel + `","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}`, "claude"},
		{"messages_stream", "/v1/messages", `{"model":"` + accessScopeClaudeModel + `","max_tokens":1,"stream":true,"messages":[{"role":"user","content":"hi"}]}`, "claude"},
		{"count_tokens", "/v1/messages/count_tokens", `{"model":"` + accessScopeClaudeModel + `","messages":[{"role":"user","content":"hi"}]}`, "claude"},
		{"responses", "/v1/responses", `{"model":"` + accessScopeCodexModel + `","input":"hi"}`, "codex"},
		{"responses_stream", "/v1/responses", `{"model":"` + accessScopeCodexModel + `","stream":true,"input":"hi"}`, "codex"},
		{"codex_direct_responses", "/backend-api/codex/responses", `{"model":"` + accessScopeCodexModel + `","stream":true,"input":"hi"}`, "codex"},
		{"responses_compact", "/v1/responses/compact", `{"model":"` + accessScopeCodexModel + `","input":"hi"}`, "codex"},
		{"alpha_search", "/v1/alpha/search", `{"id":"same-id","model":"` + accessScopeCodexModel + `","commands":{}}`, "codex"},
	}
	for _, route := range routes {
		t.Run(route.name, func(t *testing.T) {
			fixture := newAccessScopeFixture(t)
			executor := fixture.claude
			if route.provider == "codex" {
				executor = fixture.codex
			}
			post := func(key string) int {
				request := httptest.NewRequest(http.MethodPost, route.path, strings.NewReader(route.body))
				request.Header.Set("Authorization", "Bearer "+key)
				request.Header.Set("Content-Type", "application/json")
				recorder := httptest.NewRecorder()
				fixture.server.engine.ServeHTTP(recorder, request)
				return recorder.Code
			}
			for key, scope := range map[string]string{"key-a": "team-a", "key-b": "team-b"} {
				for attempt := 0; attempt < 3; attempt++ {
					status := post(key)
					used := executor.take()
					want := "access-scope-" + route.provider + "-" + scope
					if len(used) == 0 {
						t.Fatalf("%s: no credential used (status %d)", key, status)
					}
					for _, id := range used {
						if id != want {
							t.Fatalf("%s used credential %q, want %q", key, id, want)
						}
					}
				}
			}
			if status := post("key-empty"); status < 400 {
				t.Fatalf("key with no matching credential got status %d", status)
			}
			if used := executor.take(); len(used) != 0 {
				t.Fatalf("key with no matching credential used %v", used)
			}
			if status := post("key-unknown"); status != http.StatusUnauthorized {
				t.Fatalf("unknown key got status %d, want 401", status)
			}
			if status := post(""); status != http.StatusUnauthorized {
				t.Fatalf("missing key got status %d, want 401", status)
			}
		})
	}
}

func TestAccessScopeResponsesWebsocketReachesOnlyItsOwnCredential(t *testing.T) {
	fixture := newAccessScopeFixture(t)
	listener := httptest.NewServer(fixture.server.engine)
	t.Cleanup(listener.Close)
	url := "ws" + strings.TrimPrefix(listener.URL, "http") + "/v1/responses"

	for key, want := range map[string]string{"key-a": "access-scope-codex-team-a", "key-b": "access-scope-codex-team-b"} {
		conn, _, errDial := websocket.DefaultDialer.Dial(url, http.Header{"Authorization": {"Bearer " + key}})
		if errDial != nil {
			t.Fatalf("%s: dial: %v", key, errDial)
		}
		message := `{"type":"response.create","model":"` + accessScopeCodexModel + `","input":[]}`
		if errWrite := conn.WriteMessage(websocket.TextMessage, []byte(message)); errWrite != nil {
			t.Fatalf("%s: write: %v", key, errWrite)
		}
		deadline := time.Now().Add(5 * time.Second)
		var used []string
		for len(used) == 0 && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
			used = fixture.codex.take()
		}
		_ = conn.Close()
		if len(used) == 0 || slices.ContainsFunc(used, func(id string) bool { return id != want }) {
			t.Fatalf("%s used %v, want only %q", key, used, want)
		}
	}
}
