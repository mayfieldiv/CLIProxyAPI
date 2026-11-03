package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func writeScopedKeyConfig(t *testing.T, content string) string {
	t.Helper()
	file := filepath.Join(t.TempDir(), "config.yaml")
	if errWrite := os.WriteFile(file, []byte(content), 0o600); errWrite != nil {
		t.Fatalf("write config: %v", errWrite)
	}
	return file
}

func TestScopedAPIKeysLoadFromV8LayoutAndSurviveSave(t *testing.T) {
	file := writeScopedKeyConfig(t, `config-version: 8
access:
  scoped-api-keys:
    - {key: key-a, scope: team-a}
    - {key: key-b, scope: team-b}
`)
	cfg, errLoad := LoadConfig(file)
	if errLoad != nil {
		t.Fatalf("LoadConfig() error = %v", errLoad)
	}
	if len(cfg.ScopedAPIKeys) != 2 || cfg.ScopedAPIKeys[1].Key != "key-b" || cfg.ScopedAPIKeys[1].Scope != "team-b" {
		t.Fatalf("ScopedAPIKeys = %+v", cfg.ScopedAPIKeys)
	}

	if errSave := SaveConfigPreserveComments(file, cfg, true); errSave != nil {
		t.Fatalf("SaveConfigPreserveComments() error = %v", errSave)
	}
	saved, errRead := os.ReadFile(file)
	if errRead != nil {
		t.Fatalf("read saved config: %v", errRead)
	}
	var doc yaml.Node
	if errParse := yaml.Unmarshal(saved, &doc); errParse != nil {
		t.Fatalf("parse saved config: %v", errParse)
	}
	if yamlPath(doc.Content[0], "scoped-api-keys") != nil {
		t.Fatalf("save reintroduced the flat field:\n%s", saved)
	}
	if keys := yamlPath(doc.Content[0], "access.scoped-api-keys"); keys == nil || len(keys.Content) != 2 {
		t.Fatalf("save lost access.scoped-api-keys:\n%s", saved)
	}
	reloaded, errReload := LoadConfig(file)
	if errReload != nil {
		t.Fatalf("reload error = %v", errReload)
	}
	if len(reloaded.ScopedAPIKeys) != 2 {
		t.Fatalf("reloaded ScopedAPIKeys = %+v", reloaded.ScopedAPIKeys)
	}
}

func TestInvalidScopedAPIKeysAreRejected(t *testing.T) {
	for name, testCase := range map[string]struct{ entries, want string }{
		"missing_scope": {`[{key: key-a}]`, "scope must not be empty"},
		"blank_scope":   {`[{key: key-a, scope: "  "}]`, "scope must not be empty"},
		"missing_key":   {`[{scope: team-a}]`, "key must not be empty"},
		"duplicate_key": {`[{key: key-a, scope: team-a}, {key: " key-a ", scope: team-b}]`, "duplicates"},
	} {
		t.Run(name, func(t *testing.T) {
			content := "config-version: 8\naccess:\n  scoped-api-keys: " + testCase.entries + "\n"
			_, errLoad := LoadConfig(writeScopedKeyConfig(t, content))
			if errLoad == nil || !strings.Contains(errLoad.Error(), testCase.want) {
				t.Fatalf("LoadConfig() error = %v, want it to mention %q", errLoad, testCase.want)
			}
			_, errParse := ParseConfigBytes([]byte(content))
			if errParse == nil || !strings.Contains(errParse.Error(), testCase.want) {
				t.Fatalf("ParseConfigBytes() error = %v, want it to mention %q", errParse, testCase.want)
			}
		})
	}
}
