// Package accessprograms advertises, in the Codex client model catalog, the access
// programs that a scoped client's Codex logins are entitled to.
//
// The ChatGPT backend reports available_access_programs per account, so the value
// in the shared catalog template cannot be right for every login. Each Codex login
// fetches its own catalog, which is cached per login and client version.
package accessprograms

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/thinking"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/singleflight"
)

const (
	defaultBaseURL       = "https://chatgpt.com/backend-api/codex"
	defaultClientVersion = "0.159.0"
	codexOriginator      = "codex_cli_rs"
	// cacheTTL matches the Codex client's own per-account catalog cache.
	cacheTTL = 5 * time.Minute
	// fetchTimeout stays under the 5 second budget Codex gives a catalog refresh.
	fetchTimeout = 3 * time.Second
	// failureBackoff keeps a failing login from being fetched on every catalog request.
	failureBackoff  = 30 * time.Second
	maxCatalogBytes = 16 << 20
	// maxVersionsPerLogin bounds the cache, whose version key comes from the client.
	maxVersionsPerLogin = 4
)

var clientVersionPattern = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

// programsBySlug maps an upstream model slug to its available_access_programs.cyber
// list. A slug is present only when upstream sent a cyber list for it.
type programsBySlug map[string][]string

type cacheKey struct {
	authID        string
	clientVersion string
}

type cacheEntry struct {
	programs  programsBySlug
	fetchedAt time.Time
	retryAt   time.Time
	storedAt  time.Time
}

// Entitlements overlays per-login access programs onto Codex client catalogs.
// The zero value is not usable; call New.
type Entitlements struct {
	manager *coreauth.Manager
	now     func() time.Time

	mu      sync.Mutex
	entries map[cacheKey]cacheEntry
	group   singleflight.Group
}

// New returns Entitlements that fetch catalogs through manager. A nil manager
// yields Entitlements that never change a catalog.
func New(manager *coreauth.Manager) *Entitlements {
	return &Entitlements{manager: manager, now: time.Now, entries: make(map[cacheKey]cacheEntry)}
}

// Request describes the Codex client asking for the catalog.
type Request struct {
	Scope         string
	ClientVersion string
	UserAgent     string
}

// Apply replaces available_access_programs.cyber on each catalog entry with the
// programs that every credential able to serve that model in the request's scope
// accepts, so rotation never lands on a login that rejects an advertised program.
// An entry keeps its template value when the request has no scope, when no scoped
// credential serves the model, or when any serving credential is not a Codex login
// with catalog data for the model. Apply changes no other field.
func (e *Entitlements) Apply(ctx context.Context, request Request, models []map[string]any) {
	if e == nil || e.manager == nil || request.Scope == "" || len(models) == 0 {
		return
	}
	var scoped []*coreauth.Auth
	now := e.now()
	for _, auth := range e.manager.List() {
		if auth == nil || !coreauth.InAccessScope(auth, request.Scope) || !selectable(auth, now) {
			continue
		}
		scoped = append(scoped, auth)
	}
	if len(scoped) == 0 {
		return
	}
	sort.Slice(scoped, func(i, j int) bool { return scoped[i].ID < scoped[j].ID })

	type plan struct {
		entry   map[string]any
		serving []*coreauth.Auth
		model   string
	}
	plans := make([]plan, 0, len(models))
	needed := make(map[string]*coreauth.Auth)
	for _, entry := range models {
		slug, _ := entry["slug"].(string)
		model, serving := servingAuths(scoped, strings.TrimSpace(slug))
		if len(serving) == 0 || slices.ContainsFunc(serving, func(auth *coreauth.Auth) bool { return !isCodexLogin(auth) }) {
			continue
		}
		for _, auth := range serving {
			needed[auth.ID] = auth
		}
		plans = append(plans, plan{entry: entry, serving: serving, model: model})
	}
	if len(plans) == 0 {
		return
	}

	catalogs := e.catalogs(ctx, request, needed)
	for _, p := range plans {
		lists := make([][]string, 0, len(p.serving))
		for _, auth := range p.serving {
			upstreamModel := thinking.ParseSuffix(e.manager.ResolveExecutionModel(auth, p.model)).ModelName
			programs, ok := catalogs[auth.ID][upstreamModel]
			if !ok {
				break
			}
			lists = append(lists, programs)
		}
		if len(lists) != len(p.serving) {
			continue
		}
		setCyberPrograms(p.entry, intersect(lists))
	}
}

// selectable mirrors the credential selector's terminal exclusions. A login that
// needs signing in again never serves a request, so counting it would hide its
// scope's programs behind a fetch that cannot succeed. A login that is only
// cooling down still counts, since rotation returns to it.
func selectable(auth *coreauth.Auth, now time.Time) bool {
	if auth.Disabled || auth.Status == coreauth.StatusDisabled || coreauth.HasUnauthorizedAuthFailure(auth) {
		return false
	}
	if expiry, ok := auth.AccessTokenExpirationTime(); ok && !expiry.IsZero() && !expiry.After(now) {
		return false
	}
	return true
}

// servingAuths returns the scoped credentials that registered model, falling back
// to the unprefixed form when none registered a prefixed ID exactly, and the model
// ID they registered.
func servingAuths(scoped []*coreauth.Auth, model string) (string, []*coreauth.Auth) {
	if model == "" {
		return "", nil
	}
	modelRegistry := registry.GetGlobalRegistry()
	collect := func(id string) []*coreauth.Auth {
		var serving []*coreauth.Auth
		for _, auth := range scoped {
			if modelRegistry.ClientSupportsModel(auth.ID, id) {
				serving = append(serving, auth)
			}
		}
		return serving
	}
	if serving := collect(model); len(serving) > 0 {
		return model, serving
	}
	if slash := strings.Index(model, "/"); slash >= 0 {
		base := strings.TrimSpace(model[slash+1:])
		return base, collect(base)
	}
	return model, nil
}

// isCodexLogin reports whether auth is a ChatGPT login, whose catalog is per account.
// Codex API-key credentials have no per-account entitlements to read.
func isCodexLogin(auth *coreauth.Auth) bool {
	return strings.EqualFold(strings.TrimSpace(auth.Provider), "codex") && auth.AuthKind() == coreauth.AuthKindOAuth
}

func (e *Entitlements) catalogs(ctx context.Context, request Request, auths map[string]*coreauth.Auth) map[string]programsBySlug {
	clientVersion := strings.TrimSpace(request.ClientVersion)
	if !clientVersionPattern.MatchString(clientVersion) {
		clientVersion = defaultClientVersion
	}
	userAgent := strings.TrimSpace(request.UserAgent)
	if !coreauth.IsCodexClientUserAgent(userAgent) {
		userAgent = codexOriginator + "/" + clientVersion
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	result := make(map[string]programsBySlug, len(auths))
	for _, auth := range auths {
		wg.Add(1)
		go func() {
			defer wg.Done()
			programs := e.programs(ctx, auth, clientVersion, userAgent)
			mu.Lock()
			result[auth.ID] = programs
			mu.Unlock()
		}()
	}
	wg.Wait()
	return result
}

// programs returns the cached catalog for auth, refreshing it once the TTL lapses.
// A failed refresh keeps the last good catalog. The refresh is shared by concurrent
// callers and outlives a caller whose context ends first.
func (e *Entitlements) programs(ctx context.Context, auth *coreauth.Auth, clientVersion, userAgent string) programsBySlug {
	key := cacheKey{authID: auth.ID, clientVersion: clientVersion}
	if entry, ok := e.entry(key); ok {
		now := e.now()
		if (!entry.fetchedAt.IsZero() && now.Sub(entry.fetchedAt) < cacheTTL) || now.Before(entry.retryAt) {
			return entry.programs
		}
	}
	done := e.group.DoChan(fmt.Sprintf("%s\x00%s", key.authID, key.clientVersion), func() (any, error) {
		e.refresh(key, auth, userAgent)
		return nil, nil
	})
	select {
	case <-done:
	case <-ctx.Done():
	}
	entry, _ := e.entry(key)
	return entry.programs
}

func (e *Entitlements) entry(key cacheKey) (cacheEntry, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	entry, ok := e.entries[key]
	return entry, ok
}

func (e *Entitlements) refresh(key cacheKey, auth *coreauth.Auth, userAgent string) {
	ctx, cancel := context.WithTimeout(coreauth.WithCodexClientRequest(context.Background(), true), fetchTimeout)
	defer cancel()
	programs, errFetch := e.fetch(ctx, auth, key.clientVersion, userAgent)

	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.now()
	entry := e.entries[key]
	if errFetch != nil {
		entry.retryAt = now.Add(failureBackoff)
		entry.storedAt = now
		e.entries[key] = entry
		log.WithField("auth_index", auth.EnsureIndex()).Warnf("codex access programs: catalog fetch failed: %v", errFetch)
	} else {
		e.entries[key] = cacheEntry{programs: programs, fetchedAt: now, storedAt: now}
	}
	e.evictOldVersionsLocked(key.authID)
}

// evictOldVersionsLocked keeps the most recently stored client versions of a login.
func (e *Entitlements) evictOldVersionsLocked(authID string) {
	var keys []cacheKey
	for key := range e.entries {
		if key.authID == authID {
			keys = append(keys, key)
		}
	}
	if len(keys) <= maxVersionsPerLogin {
		return
	}
	sort.Slice(keys, func(i, j int) bool { return e.entries[keys[i]].storedAt.After(e.entries[keys[j]].storedAt) })
	for _, key := range keys[maxVersionsPerLogin:] {
		delete(e.entries, key)
	}
}

func (e *Entitlements) fetch(ctx context.Context, auth *coreauth.Auth, clientVersion, userAgent string) (programsBySlug, error) {
	baseURL := defaultBaseURL
	if auth.Attributes != nil {
		if configured := strings.TrimSpace(auth.Attributes["base_url"]); configured != "" {
			baseURL = configured
		}
	}
	modelsURL := strings.TrimRight(baseURL, "/") + "/models?" + url.Values{"client_version": {clientVersion}}.Encode()

	headers := make(http.Header)
	headers.Set("Accept", "application/json")
	headers.Set("Originator", codexOriginator)
	headers.Set("User-Agent", userAgent)
	if accountID, _ := auth.Metadata["account_id"].(string); strings.TrimSpace(accountID) != "" {
		headers.Set("Chatgpt-Account-Id", strings.TrimSpace(accountID))
	}
	request, errRequest := e.manager.NewHttpRequest(ctx, auth, http.MethodGet, modelsURL, nil, headers)
	if errRequest != nil {
		return nil, errRequest
	}
	response, errDo := e.manager.HttpRequest(ctx, auth, request)
	if errDo != nil {
		return nil, errDo
	}
	defer func() {
		if errClose := response.Body.Close(); errClose != nil {
			log.Debugf("codex access programs: close response body: %v", errClose)
		}
	}()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxCatalogBytes))
		return nil, fmt.Errorf("models request returned status %d", response.StatusCode)
	}
	return decodeCatalog(io.LimitReader(response.Body, maxCatalogBytes))
}

func decodeCatalog(body io.Reader) (programsBySlug, error) {
	var payload struct {
		Models []struct {
			Slug           string `json:"slug"`
			AccessPrograms *struct {
				Cyber *[]string `json:"cyber"`
			} `json:"available_access_programs"`
		} `json:"models"`
	}
	if errDecode := json.NewDecoder(body).Decode(&payload); errDecode != nil {
		return nil, fmt.Errorf("decode models response: %w", errDecode)
	}
	if payload.Models == nil {
		return nil, fmt.Errorf("models response has no models array")
	}
	programs := make(programsBySlug, len(payload.Models))
	for _, model := range payload.Models {
		slug := strings.TrimSpace(model.Slug)
		if slug == "" || model.AccessPrograms == nil || model.AccessPrograms.Cyber == nil {
			continue
		}
		programs[slug] = slices.Clone(*model.AccessPrograms.Cyber)
	}
	return programs, nil
}

// intersect keeps the programs present in every list, in the first list's order.
func intersect(lists [][]string) []string {
	result := make([]string, 0, len(lists[0]))
	for _, program := range lists[0] {
		if slices.Contains(result, program) {
			continue
		}
		inAll := true
		for _, other := range lists[1:] {
			if !slices.Contains(other, program) {
				inAll = false
				break
			}
		}
		if inAll {
			result = append(result, program)
		}
	}
	return result
}

func setCyberPrograms(entry map[string]any, programs []string) {
	access := make(map[string]any)
	if existing, ok := entry["available_access_programs"].(map[string]any); ok {
		for key, value := range existing {
			access[key] = value
		}
	}
	cyber := make([]any, len(programs))
	for i, program := range programs {
		cyber[i] = program
	}
	access["cyber"] = cyber
	entry["available_access_programs"] = access
}
