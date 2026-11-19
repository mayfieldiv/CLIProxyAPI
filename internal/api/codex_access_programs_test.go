package api

import (
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"

	proxyconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
)

// personalAccountCatalog is what a live personal account received from the ChatGPT backend.
var personalAccountCatalog = map[string][]string{
	"gpt-6-sol":     {"standard", "daybreak_blue"},
	"gpt-6-luna":    {"standard", "daybreak_blue"},
	"gpt-6.2-sol":   {"standard"},
	"gpt-6.2-astra": {"standard"},
	"gpt-6.1-sol":   {"standard"},
	"gpt-6.1-terra": {"standard"},
	"gpt-6-astra":   {"standard"},
}

// perAccountModelsUpstream serves each ChatGPT account the catalog registered for it.
type perAccountModelsUpstream struct {
	server *httptest.Server

	mu       sync.Mutex
	catalogs map[string]map[string][]string
	requests map[string]int
}

func newPerAccountModelsUpstream(t *testing.T, catalogs map[string]map[string][]string) *perAccountModelsUpstream {
	t.Helper()
	upstream := &perAccountModelsUpstream{catalogs: catalogs, requests: make(map[string]int)}
	upstream.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		account := r.Header.Get("Chatgpt-Account-Id")
		upstream.mu.Lock()
		upstream.requests[account]++
		catalog, ok := upstream.catalogs[account]
		upstream.mu.Unlock()
		if r.URL.Path != "/models" || !ok || r.Header.Get("Authorization") != "Bearer token-"+account {
			http.Error(w, `{"detail":"forbidden"}`, http.StatusForbidden)
			return
		}
		models := make([]map[string]any, 0, len(catalog))
		for slug, cyber := range catalog {
			models = append(models, map[string]any{
				"slug":                      slug,
				"display_name":              "upstream-only display name",
				"priority":                  -1,
				"available_access_programs": map[string]any{"cyber": cyber},
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"models": models})
	}))
	t.Cleanup(upstream.server.Close)
	return upstream
}

func (u *perAccountModelsUpstream) requestCount(account string) int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.requests[account]
}

type codexAccessProgramsFixture struct {
	server   *Server
	upstream *perAccountModelsUpstream
}

func newCodexAccessProgramsFixture(t *testing.T, catalogs map[string]map[string][]string) *codexAccessProgramsFixture {
	t.Helper()
	t.Cleanup(func() { auth.SetAccessScopeEnforced(false) })
	cfg := &proxyconfig.Config{
		SDKConfig: sdkconfig.SDKConfig{
			APIKeys: []string{"key-unscoped"},
			ScopedAPIKeys: []sdkconfig.ScopedAPIKey{
				{Key: "key-personal", Scope: "personal"},
				{Key: "key-immybot", Scope: "immybot"},
				{Key: "key-cyberfox", Scope: "cyberfox"},
			},
		},
	}
	server := newTestServerWithConfig(t, cfg)
	server.handlers.AuthManager.RegisterExecutor(executor.NewCodexExecutor(cfg))
	return &codexAccessProgramsFixture{server: server, upstream: newPerAccountModelsUpstream(t, catalogs)}
}

// addLogin registers a Codex login whose account ID and credential ID are both account.
func (f *codexAccessProgramsFixture) addLogin(t *testing.T, account, scope string, models ...string) {
	t.Helper()
	infos := make([]*registry.ModelInfo, 0, len(models))
	for _, model := range models {
		infos = append(infos, &registry.ModelInfo{ID: model, Object: "model", OwnedBy: "openai", Type: "codex"})
	}
	registry.GetGlobalRegistry().RegisterClient(account, "codex", infos)
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(account) })
	credential := &auth.Auth{
		ID:         account,
		Provider:   "codex",
		Status:     auth.StatusActive,
		Attributes: map[string]string{"base_url": f.upstream.server.URL},
		Metadata: map[string]any{
			"type":                              "codex",
			"access_token":                      "token-" + account,
			"account_id":                        account,
			coreexecutor.AccessScopeMetadataKey: scope,
		},
	}
	if _, errRegister := f.server.handlers.AuthManager.Register(t.Context(), credential); errRegister != nil {
		t.Fatalf("register %s: %v", account, errRegister)
	}
}

// catalog returns the Codex client catalog served to key, by slug.
func (f *codexAccessProgramsFixture) catalog(t *testing.T, key string) map[string]map[string]any {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "/v1/models?client_version=0.161.0", nil)
	request.Header.Set("Authorization", "Bearer "+key)
	request.Header.Set("User-Agent", "codex_cli_rs/0.161.0 (Mac OS 26.3.1; arm64) iTerm.app/3.6.9")
	recorder := httptest.NewRecorder()
	f.server.engine.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("%s: status %d: %s", key, recorder.Code, recorder.Body.String())
	}
	var payload struct {
		Models []map[string]any `json:"models"`
	}
	if errDecode := json.Unmarshal(recorder.Body.Bytes(), &payload); errDecode != nil {
		t.Fatalf("%s: decode catalog: %v", key, errDecode)
	}
	bySlug := make(map[string]map[string]any, len(payload.Models))
	for _, model := range payload.Models {
		slug, _ := model["slug"].(string)
		bySlug[slug] = model
	}
	return bySlug
}

func cyberPrograms(t *testing.T, catalog map[string]map[string]any, slug string) []string {
	t.Helper()
	entry, ok := catalog[slug]
	if !ok {
		t.Fatalf("catalog has no %s", slug)
	}
	access, _ := entry["available_access_programs"].(map[string]any)
	raw, _ := access["cyber"].([]any)
	programs := make([]string, 0, len(raw))
	for _, program := range raw {
		value, _ := program.(string)
		programs = append(programs, value)
	}
	return programs
}

func assertCyberPrograms(t *testing.T, catalog map[string]map[string]any, want map[string][]string) {
	t.Helper()
	for slug, programs := range want {
		if got := cyberPrograms(t, catalog, slug); !slices.Equal(got, programs) {
			t.Errorf("%s cyber = %v, want %v", slug, got, programs)
		}
	}
}

func TestCodexClientCatalogAdvertisesEachScopesOwnEntitlements(t *testing.T) {
	cyberfoxCatalog := maps.Clone(personalAccountCatalog)
	cyberfoxCatalog["gpt-6-sol"] = []string{"standard", "daybreak_red"}
	cyberfoxCatalog["gpt-6-luna"] = []string{"standard"}
	fixture := newCodexAccessProgramsFixture(t, map[string]map[string][]string{
		"account-personal": personalAccountCatalog,
		"account-cyberfox": cyberfoxCatalog,
	})
	models := slices.Collect(maps.Keys(personalAccountCatalog))
	fixture.addLogin(t, "account-personal", "personal", models...)
	fixture.addLogin(t, "account-cyberfox", "cyberfox", models...)

	assertCyberPrograms(t, fixture.catalog(t, "key-personal"), map[string][]string{
		"gpt-6-sol":   {"standard", "daybreak_blue"},
		"gpt-6-luna":  {"standard", "daybreak_blue"},
		"gpt-6.1-sol": {"standard"},
		"gpt-6-astra": {"standard"},
	})
	assertCyberPrograms(t, fixture.catalog(t, "key-cyberfox"), map[string][]string{
		"gpt-6-sol":  {"standard", "daybreak_red"},
		"gpt-6-luna": {"standard"},
	})
	// immybot has no login, so it neither sees another scope's entitlements nor fetches any.
	assertCyberPrograms(t, fixture.catalog(t, "key-immybot"), map[string][]string{
		"gpt-6-sol":  {"standard"},
		"gpt-6-luna": {"standard"},
	})
	if personal, cyberfox := fixture.upstream.requestCount("account-personal"), fixture.upstream.requestCount("account-cyberfox"); personal != 1 || cyberfox != 1 {
		t.Fatalf("upstream requests personal=%d cyberfox=%d, want 1 each", personal, cyberfox)
	}
}

func TestCodexClientCatalogIntersectsEntitlementsAcrossAScopesLogins(t *testing.T) {
	fixture := newCodexAccessProgramsFixture(t, map[string]map[string][]string{
		"account-immybot-a": {
			"gpt-6-sol":   {"standard", "daybreak_blue", "daybreak_red"},
			"gpt-6-luna":  {"standard", "daybreak_blue"},
			"gpt-6.1-sol": {"standard", "daybreak_blue"},
		},
		"account-immybot-b": {
			"gpt-6-sol":  {"daybreak_red", "standard"},
			"gpt-6-luna": {"standard"},
		},
	})
	fixture.addLogin(t, "account-immybot-a", "immybot", "gpt-6-sol", "gpt-6-luna", "gpt-6.1-sol")
	fixture.addLogin(t, "account-immybot-b", "immybot", "gpt-6-sol", "gpt-6-luna")

	assertCyberPrograms(t, fixture.catalog(t, "key-immybot"), map[string][]string{
		"gpt-6-sol":  {"standard", "daybreak_red"},
		"gpt-6-luna": {"standard"},
		// Only login A serves gpt-6.1-sol, so rotation can only land there.
		"gpt-6.1-sol": {"standard", "daybreak_blue"},
	})
}

func TestCodexClientCatalogFallsBackToTheTemplate(t *testing.T) {
	fixture := newCodexAccessProgramsFixture(t, map[string]map[string][]string{
		"account-personal": personalAccountCatalog,
	})
	fixture.addLogin(t, "account-personal", "personal", "gpt-6-sol")
	// The upstream refuses this login, so there is no catalog for it yet.
	fixture.addLogin(t, "account-cyberfox", "cyberfox", "gpt-6-sol")

	assertCyberPrograms(t, fixture.catalog(t, "key-cyberfox"), map[string][]string{"gpt-6-sol": {"standard"}})
	assertCyberPrograms(t, fixture.catalog(t, "key-unscoped"), map[string][]string{"gpt-6-sol": {"standard"}})
	if got := fixture.upstream.requestCount("account-personal"); got != 0 {
		t.Fatalf("unscoped catalog fetched personal entitlements %d times", got)
	}
}

func TestCodexClientCatalogChangesOnlyAccessPrograms(t *testing.T) {
	fixture := newCodexAccessProgramsFixture(t, map[string]map[string][]string{
		"account-personal": personalAccountCatalog,
	})
	fixture.addLogin(t, "account-personal", "personal", "gpt-6-sol", "gpt-6-luna")

	unscoped := fixture.catalog(t, "key-unscoped")
	scoped := fixture.catalog(t, "key-personal")
	if !slices.Equal(slices.Sorted(maps.Keys(scoped)), slices.Sorted(maps.Keys(unscoped))) {
		t.Fatalf("scoped catalog models %v differ from unscoped %v", slices.Sorted(maps.Keys(scoped)), slices.Sorted(maps.Keys(unscoped)))
	}
	for _, slug := range []string{"gpt-6-sol", "gpt-6-luna"} {
		want := maps.Clone(unscoped[slug])
		want["available_access_programs"] = map[string]any{"cyber": []any{"standard", "daybreak_blue"}}
		if !reflect.DeepEqual(scoped[slug], want) {
			gotJSON, _ := json.Marshal(scoped[slug])
			wantJSON, _ := json.Marshal(want)
			t.Fatalf("%s:\n got %s\nwant %s", slug, gotJSON, wantJSON)
		}
		if display, _ := scoped[slug]["display_name"].(string); strings.Contains(display, "upstream") {
			t.Fatalf("%s took display_name %q from upstream", slug, display)
		}
	}
}
