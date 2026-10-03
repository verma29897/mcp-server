package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// write puts content in a temp file and returns its path.
func write(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func TestEnvFileFillsGaps(t *testing.T) {
	path := write(t, `
# a comment
LOG_LEVEL=debug
MCP_TRANSPORT = http
export BACKEND_MODE=memory
QUOTED="a value with spaces and a # hash"
SINGLE='raw $NOT_EXPANDED value'
EMPTY=
TRAILING=value # this comment is stripped
HASH_IN_VALUE=pass#word
ESCAPED="line\none\ttab"
`)
	for _, k := range []string{"LOG_LEVEL", "MCP_TRANSPORT", "BACKEND_MODE", "QUOTED", "SINGLE", "EMPTY", "TRAILING", "HASH_IN_VALUE", "ESCAPED"} {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}

	res, err := LoadEnvFile(path)
	if err != nil {
		t.Fatalf("LoadEnvFile: %v", err)
	}
	if res.Applied != 9 {
		t.Errorf("applied = %d, want 9", res.Applied)
	}

	want := map[string]string{
		"LOG_LEVEL":     "debug",
		"MCP_TRANSPORT": "http",
		"BACKEND_MODE":  "memory",
		"QUOTED":        "a value with spaces and a # hash",
		"SINGLE":        "raw $NOT_EXPANDED value",
		"EMPTY":         "",
		"TRAILING":      "value",
		"HASH_IN_VALUE": "pass#word",
		"ESCAPED":       "line\none\ttab",
	}
	for k, v := range want {
		if got := os.Getenv(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
}

func TestRealEnvironmentAlwaysWins(t *testing.T) {
	// The rule the whole feature rests on. An .env that could override the
	// environment would mean a stray file in a container image silently
	// replacing what the orchestrator injected - and the process would start
	// happily with the wrong backend, the wrong tenant or the wrong token.
	path := write(t, "BACKEND_BASE_URL=https://from-the-file.example\nLOG_LEVEL=debug\n")

	t.Setenv("BACKEND_BASE_URL", "https://from-the-orchestrator.example")
	os.Unsetenv("LOG_LEVEL")

	res, err := LoadEnvFile(path)
	if err != nil {
		t.Fatalf("LoadEnvFile: %v", err)
	}

	if got := os.Getenv("BACKEND_BASE_URL"); got != "https://from-the-orchestrator.example" {
		t.Fatalf("BACKEND_BASE_URL = %q; the file overrode the real environment", got)
	}
	if got := os.Getenv("LOG_LEVEL"); got != "debug" {
		t.Errorf("LOG_LEVEL = %q, want the file to have filled the gap", got)
	}
	if len(res.Skipped) != 1 || res.Skipped[0] != "BACKEND_BASE_URL" {
		t.Errorf("skipped = %v, want the overridden name reported so an operator can see it", res.Skipped)
	}
}

func TestEmptyEnvironmentValueStillCounts(t *testing.T) {
	// `FOO=` in the real environment is a deliberate empty value, not an
	// absence. Treating it as a gap would let the file resurrect a setting the
	// operator explicitly cleared.
	path := write(t, "BACKEND_API_TOKEN=from-the-file\n")
	t.Setenv("BACKEND_API_TOKEN", "")

	if _, err := LoadEnvFile(path); err != nil {
		t.Fatalf("LoadEnvFile: %v", err)
	}
	if got := os.Getenv("BACKEND_API_TOKEN"); got != "" {
		t.Errorf("BACKEND_API_TOKEN = %q; an explicitly empty value was overwritten", got)
	}
}

func TestMissingFileIsNotAnError(t *testing.T) {
	// Production has no .env, and the server must start regardless.
	res, err := LoadEnvFile(filepath.Join(t.TempDir(), "does-not-exist"))
	if err != nil {
		t.Fatalf("a missing file was treated as an error: %v", err)
	}
	if res.Path != "" || res.Applied != 0 {
		t.Errorf("result = %+v, want an empty one", res)
	}
}

func TestMalformedFileIsFatal(t *testing.T) {
	// Silently ignoring a line the operator believed was setting a credential
	// is the failure this package exists to prevent, so a bad line stops
	// startup rather than being skipped.
	tests := []struct {
		name    string
		content string
		wantErr string
	}{
		{"no equals sign", "LOG_LEVEL debug\n", "expected KEY=VALUE"},
		{"empty name", "=value\n", "empty variable name"},
		{"name starts with a digit", "1BACKEND=x\n", "starts with a digit"},
		{"space in the name", "LOG LEVEL=debug\n", "contains"},
		{"dash in the name", "LOG-LEVEL=debug\n", "contains"},
		{"unterminated double quote", `TOKEN="abc` + "\n", "unterminated"},
		{"unterminated single quote", "TOKEN='abc\n", "unterminated"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadEnvFile(write(t, tc.content))
			if err == nil {
				t.Fatalf("LoadEnvFile accepted %q", tc.content)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want it to mention %q", err, tc.wantErr)
			}
			// The message has to name the line, or an operator with a
			// hundred-line file has nothing to go on.
			if !strings.Contains(err.Error(), ":1:") {
				t.Errorf("error = %q, want it to name the line number", err)
			}
		})
	}
}

func TestNoInterpolationOrSubstitution(t *testing.T) {
	// Interpolation makes a config file depend on evaluation order, and command
	// substitution makes it executable. Neither is worth the surprise in a file
	// that carries credentials, so both are stored literally.
	path := write(t, "A=literal\nB=$A\nC=${A}\nD=`id`\n")
	for _, k := range []string{"A", "B", "C", "D"} {
		os.Unsetenv(k)
	}
	t.Cleanup(func() {
		for _, k := range []string{"A", "B", "C", "D"} {
			os.Unsetenv(k)
		}
	})

	if _, err := LoadEnvFile(path); err != nil {
		t.Fatalf("LoadEnvFile: %v", err)
	}
	for k, want := range map[string]string{"B": "$A", "C": "${A}", "D": "`id`"} {
		if got := os.Getenv(k); got != want {
			t.Errorf("%s = %q, want the literal %q", k, got, want)
		}
	}
}

func TestDirectoryIsRefused(t *testing.T) {
	if _, err := LoadEnvFile(t.TempDir()); err == nil {
		t.Fatal("a directory was accepted as an env file")
	}
}

func TestLoadedValuesReachTheConfiguration(t *testing.T) {
	// The end-to-end property: a value in the file shapes the resolved
	// configuration exactly as an exported variable would.
	path := write(t, `
MCP_TRANSPORT=http
MCP_ALLOW_INSECURE_HTTP=true
MCP_HTTP_ADDR=127.0.0.1:9999
MCP_LOCAL_SCOPES=customer:read,customer:search
LOG_LEVEL=warn
`)
	for _, k := range []string{"MCP_TRANSPORT", "MCP_ALLOW_INSECURE_HTTP", "MCP_HTTP_ADDR", "MCP_LOCAL_SCOPES", "LOG_LEVEL"} {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}

	if _, err := LoadEnvFile(path); err != nil {
		t.Fatalf("LoadEnvFile: %v", err)
	}
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Transport != TransportHTTP {
		t.Errorf("transport = %q, want http", cfg.Transport)
	}
	if cfg.HTTP.Addr != "127.0.0.1:9999" {
		t.Errorf("addr = %q", cfg.HTTP.Addr)
	}
	if len(cfg.Auth.LocalScopes) != 2 {
		t.Errorf("local scopes = %v, want the two from the file", cfg.Auth.LocalScopes)
	}
}

func TestFileCannotWidenAGrantTheEnvironmentSet(t *testing.T) {
	// The precedence rule stated as a security property: an .env dropped into a
	// deployment cannot escalate what the orchestrator granted.
	path := write(t, "MCP_LOCAL_SCOPES=customer:read,customer:search,customer:delete,notification:send\n")
	t.Setenv("MCP_LOCAL_SCOPES", "customer:read")

	if _, err := LoadEnvFile(path); err != nil {
		t.Fatalf("LoadEnvFile: %v", err)
	}
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Auth.LocalScopes) != 1 || cfg.Auth.LocalScopes[0] != "customer:read" {
		t.Fatalf("scopes = %v; the file widened a grant the environment had narrowed", cfg.Auth.LocalScopes)
	}
}
