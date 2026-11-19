package accessprograms

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

const testScope = "accessprograms-test-scope"

// upstreamCatalog stands in for chatgpt.com's per-account models endpoint.
type upstreamCatalog struct {
	server   *httptest.Server
	requests atomic.Int32

	mu       sync.Mutex
	status   int
	programs map[string][]string
	gate     chan struct{}
	lastSeen *http.Request
}

func newUpstreamCatalog(t *testing.T, programs map[string][]string) *upstreamCatalog {
	t.Helper()
	upstream := &upstreamCatalog{status: http.StatusOK, programs: programs}
	upstream.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstream.requests.Add(1)
		upstream.mu.Lock()
		gate, status, programs := upstream.gate, upstream.status, upstream.programs
		upstream.lastSeen = r.Clone(r.Context())
		upstream.mu.Unlock()
		if gate != nil {
			<-gate
		}
		if status != http.StatusOK {
			http.Error(w, `{"detail":"unavailable"}`, status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", "stable-catalog-etag")
		_ = json.NewEncoder(w).Encode(catalogBody(programs))
	}))
	t.Cleanup(upstream.server.Close)
	return upstream
}

func catalogBody(programs map[string][]string) map[string]any {
	models := make([]map[string]any, 0, len(programs))
	for slug, cyber := range programs {
		models = append(models, map[string]any{
			"slug":                      slug,
			"display_name":              "upstream " + slug,
			"available_access_programs": map[string]any{"cyber": cyber},
		})
	}
	return map[string]any{"models": models}
}

func (u *upstreamCatalog) set(status int, programs map[string][]string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.status = status
	if programs != nil {
		u.programs = programs
	}
}

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

type fixture struct {
	manager      *coreauth.Manager
	entitlements *Entitlements
	clock        *testClock
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	manager := coreauth.NewManager(nil, nil, nil)
	manager.RegisterExecutor(executor.NewCodexExecutor(&config.Config{}))
	clock := &testClock{now: time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)}
	entitlements := New(manager)
	entitlements.now = clock.Now
	return &fixture{manager: manager, entitlements: entitlements, clock: clock}
}

func (f *fixture) addCodexLogin(t *testing.T, id, scope string, upstream *upstreamCatalog, models ...string) {
	t.Helper()
	credential := &coreauth.Auth{
		ID:         id,
		Provider:   "codex",
		Status:     coreauth.StatusActive,
		Attributes: map[string]string{"base_url": upstream.server.URL},
		Metadata: map[string]any{
			"type":                                  "codex",
			"access_token":                          "token-" + id,
			"account_id":                            "account-" + id,
			cliproxyexecutor.AccessScopeMetadataKey: scope,
		},
	}
	f.register(t, credential, models)
}

func (f *fixture) register(t *testing.T, credential *coreauth.Auth, models []string) {
	t.Helper()
	infos := make([]*registry.ModelInfo, 0, len(models))
	for _, model := range models {
		infos = append(infos, &registry.ModelInfo{ID: model})
	}
	registry.GetGlobalRegistry().RegisterClient(credential.ID, credential.Provider, infos)
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(credential.ID) })
	if _, errRegister := f.manager.Register(t.Context(), credential); errRegister != nil {
		t.Fatalf("register %s: %v", credential.ID, errRegister)
	}
}

func templateEntry(slug string) map[string]any {
	return map[string]any{
		"slug":                      slug,
		"display_name":              "template " + slug,
		"available_access_programs": map[string]any{"cyber": []any{"standard"}},
	}
}

func (f *fixture) cyber(t *testing.T, slug string) []any {
	t.Helper()
	models := []map[string]any{templateEntry(slug)}
	f.entitlements.Apply(t.Context(), Request{Scope: testScope, ClientVersion: "0.161.0"}, models)
	cyber, _ := models[0]["available_access_programs"].(map[string]any)["cyber"].([]any)
	return cyber
}

func wantCyber(t *testing.T, got []any, want ...string) {
	t.Helper()
	gotStrings := make([]string, 0, len(got))
	for _, program := range got {
		value, _ := program.(string)
		gotStrings = append(gotStrings, value)
	}
	if !slices.Equal(gotStrings, want) {
		t.Fatalf("cyber = %v, want %v", gotStrings, want)
	}
}

func TestFetchSendsTheLoginsCredentialsAndClientVersion(t *testing.T) {
	f := newFixture(t)
	upstream := newUpstreamCatalog(t, map[string][]string{"gpt-6-sol": {"standard", "daybreak_blue"}})
	f.addCodexLogin(t, "ap-headers", testScope, upstream, "gpt-6-sol")

	wantCyber(t, f.cyber(t, "gpt-6-sol"), "standard", "daybreak_blue")

	upstream.mu.Lock()
	seen := upstream.lastSeen
	upstream.mu.Unlock()
	if seen.URL.Path != "/models" || seen.URL.Query().Get("client_version") != "0.161.0" {
		t.Fatalf("upstream request = %s, want /models?client_version=0.161.0", seen.URL)
	}
	for header, want := range map[string]string{
		"Authorization":      "Bearer token-ap-headers",
		"Chatgpt-Account-Id": "account-ap-headers",
		"Originator":         "codex_cli_rs",
	} {
		if got := seen.Header.Get(header); got != want {
			t.Fatalf("%s = %q, want %q", header, got, want)
		}
	}
}

func TestCatalogIsCachedForTheTTLThenRefetched(t *testing.T) {
	f := newFixture(t)
	upstream := newUpstreamCatalog(t, map[string][]string{"gpt-6-sol": {"standard", "daybreak_blue"}})
	f.addCodexLogin(t, "ap-ttl", testScope, upstream, "gpt-6-sol")

	wantCyber(t, f.cyber(t, "gpt-6-sol"), "standard", "daybreak_blue")
	// Entitlements can change while the catalog ETag stays the same.
	upstream.set(http.StatusOK, map[string][]string{"gpt-6-sol": {}})

	f.clock.Advance(cacheTTL - time.Second)
	wantCyber(t, f.cyber(t, "gpt-6-sol"), "standard", "daybreak_blue")
	if got := upstream.requests.Load(); got != 1 {
		t.Fatalf("upstream requests within TTL = %d, want 1", got)
	}

	f.clock.Advance(time.Second)
	wantCyber(t, f.cyber(t, "gpt-6-sol"))
	if got := upstream.requests.Load(); got != 2 {
		t.Fatalf("upstream requests after TTL = %d, want 2", got)
	}
}

func TestRefreshFailureKeepsTheLastGoodCatalog(t *testing.T) {
	f := newFixture(t)
	upstream := newUpstreamCatalog(t, map[string][]string{"gpt-6-sol": {"standard", "daybreak_blue"}})
	f.addCodexLogin(t, "ap-failure", testScope, upstream, "gpt-6-sol")

	wantCyber(t, f.cyber(t, "gpt-6-sol"), "standard", "daybreak_blue")
	upstream.set(http.StatusInternalServerError, nil)
	f.clock.Advance(cacheTTL)
	wantCyber(t, f.cyber(t, "gpt-6-sol"), "standard", "daybreak_blue")
	if got := upstream.requests.Load(); got != 2 {
		t.Fatalf("upstream requests after failed refresh = %d, want 2", got)
	}

	f.clock.Advance(failureBackoff - time.Second)
	wantCyber(t, f.cyber(t, "gpt-6-sol"), "standard", "daybreak_blue")
	if got := upstream.requests.Load(); got != 2 {
		t.Fatalf("upstream requests during failure backoff = %d, want 2", got)
	}

	upstream.set(http.StatusOK, map[string][]string{"gpt-6-sol": {"standard"}})
	f.clock.Advance(time.Second)
	wantCyber(t, f.cyber(t, "gpt-6-sol"), "standard")
	if got := upstream.requests.Load(); got != 3 {
		t.Fatalf("upstream requests after backoff = %d, want 3", got)
	}
}

func TestConcurrentRequestsShareOneFetch(t *testing.T) {
	f := newFixture(t)
	upstream := newUpstreamCatalog(t, map[string][]string{"gpt-6-sol": {"standard", "daybreak_blue"}})
	gate := make(chan struct{})
	upstream.mu.Lock()
	upstream.gate = gate
	upstream.mu.Unlock()
	f.addCodexLogin(t, "ap-concurrent", testScope, upstream, "gpt-6-sol")

	results := make([][]any, 8)
	var wg sync.WaitGroup
	for i := range results {
		wg.Go(func() { results[i] = f.cyber(t, "gpt-6-sol") })
	}
	for upstream.requests.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	close(gate)
	wg.Wait()

	if got := upstream.requests.Load(); got != 1 {
		t.Fatalf("upstream requests = %d, want 1", got)
	}
	for _, result := range results {
		wantCyber(t, result, "standard", "daybreak_blue")
	}
}

func TestTemplateValueIsKeptWithoutCompleteData(t *testing.T) {
	t.Run("first fetch fails", func(t *testing.T) {
		f := newFixture(t)
		upstream := newUpstreamCatalog(t, nil)
		upstream.set(http.StatusUnauthorized, nil)
		f.addCodexLogin(t, "ap-never-fetched", testScope, upstream, "gpt-6-sol")
		wantCyber(t, f.cyber(t, "gpt-6-sol"), "standard")
	})
	t.Run("model missing upstream", func(t *testing.T) {
		f := newFixture(t)
		upstream := newUpstreamCatalog(t, map[string][]string{"gpt-6-luna": {"standard", "daybreak_blue"}})
		f.addCodexLogin(t, "ap-missing-model", testScope, upstream, "gpt-6-sol")
		wantCyber(t, f.cyber(t, "gpt-6-sol"), "standard")
	})
	t.Run("model also served by a non-Codex credential", func(t *testing.T) {
		f := newFixture(t)
		upstream := newUpstreamCatalog(t, map[string][]string{"gpt-6-sol": {"standard", "daybreak_blue"}})
		f.addCodexLogin(t, "ap-mixed-codex", testScope, upstream, "gpt-6-sol")
		f.register(t, &coreauth.Auth{
			ID:         "ap-mixed-compat",
			Provider:   "openai-compatibility",
			Status:     coreauth.StatusActive,
			Attributes: map[string]string{"api_key": "sk-test"},
			Metadata:   map[string]any{cliproxyexecutor.AccessScopeMetadataKey: testScope},
		}, []string{"gpt-6-sol"})
		wantCyber(t, f.cyber(t, "gpt-6-sol"), "standard")
		if got := upstream.requests.Load(); got != 0 {
			t.Fatalf("upstream requests = %d, want 0", got)
		}
	})
	t.Run("no scope", func(t *testing.T) {
		f := newFixture(t)
		upstream := newUpstreamCatalog(t, map[string][]string{"gpt-6-sol": {"standard", "daybreak_blue"}})
		f.addCodexLogin(t, "ap-no-scope", testScope, upstream, "gpt-6-sol")
		models := []map[string]any{templateEntry("gpt-6-sol")}
		f.entitlements.Apply(t.Context(), Request{ClientVersion: "0.161.0"}, models)
		wantCyber(t, models[0]["available_access_programs"].(map[string]any)["cyber"].([]any), "standard")
		if got := upstream.requests.Load(); got != 0 {
			t.Fatalf("upstream requests = %d, want 0", got)
		}
	})
}
