package config

import (
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load with no environment: %v", err)
	}

	// The zero-configuration path must produce a working server, so a first
	// run needs no environment at all.
	if cfg.Transport != TransportStdio {
		t.Errorf("transport = %q, want %q", cfg.Transport, TransportStdio)
	}
	if cfg.Backend.Mode != BackendMemory {
		t.Errorf("backend mode = %q, want %q", cfg.Backend.Mode, BackendMemory)
	}
	if cfg.Identity.Name == "" || cfg.Identity.Version == "" {
		t.Error("identity must have a name and version")
	}
	if cfg.Observability.LogLevel != slog.LevelInfo {
		t.Errorf("log level = %v, want info", cfg.Observability.LogLevel)
	}
}

func TestLoadFromEnvironment(t *testing.T) {
	t.Setenv("MCP_TRANSPORT", "http")
	// Unauthenticated HTTP is a deliberate choice the configuration makes the
	// operator state; this test is about parsing, not about that decision.
	t.Setenv("MCP_ALLOW_INSECURE_HTTP", "true")
	t.Setenv("MCP_HTTP_ADDR", "0.0.0.0:9090")
	t.Setenv("MCP_HTTP_PATH", "/mcp/v1")
	t.Setenv("MCP_HTTP_STATELESS", "true")
	t.Setenv("CURSOR_SECRET", "shared-across-replicas")
	t.Setenv("MCP_HTTP_SESSION_TIMEOUT", "45s")
	t.Setenv("BACKEND_MODE", "http")
	t.Setenv("BACKEND_BASE_URL", "https://api.example.com/")
	t.Setenv("BACKEND_TIMEOUT", "3s")
	t.Setenv("LOG_LEVEL", "debug")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Transport != TransportHTTP {
		t.Errorf("transport = %q, want http", cfg.Transport)
	}
	if cfg.HTTP.Addr != "0.0.0.0:9090" || cfg.HTTP.Path != "/mcp/v1" || !cfg.HTTP.Stateless {
		t.Errorf("HTTP config = %+v", cfg.HTTP)
	}
	if cfg.HTTP.SessionTimeout != 45*time.Second {
		t.Errorf("session timeout = %s, want 45s", cfg.HTTP.SessionTimeout)
	}
	// A trailing slash on the base URL would produce "//customers" paths.
	if cfg.Backend.BaseURL != "https://api.example.com" {
		t.Errorf("base URL = %q, want the trailing slash trimmed", cfg.Backend.BaseURL)
	}
	if cfg.Observability.LogLevel != slog.LevelDebug {
		t.Errorf("log level = %v, want debug", cfg.Observability.LogLevel)
	}
}

func TestLoadValidationErrors(t *testing.T) {
	tests := []struct {
		name    string
		env     map[string]string
		wantErr string
	}{
		{
			name:    "unknown transport",
			env:     map[string]string{"MCP_TRANSPORT": "grpc"},
			wantErr: "MCP_TRANSPORT",
		},
		{
			name:    "unknown backend mode",
			env:     map[string]string{"BACKEND_MODE": "cassandra"},
			wantErr: "BACKEND_MODE",
		},
		{
			name:    "http backend without a base URL",
			env:     map[string]string{"BACKEND_MODE": "http"},
			wantErr: "BACKEND_BASE_URL is required",
		},
		{
			name: "http backend with a non-http base URL",
			env: map[string]string{
				"BACKEND_MODE":     "http",
				"BACKEND_BASE_URL": "postgres://db/customers",
			},
			wantErr: "must start with http",
		},
		{
			name: "http transport with a relative path",
			env: map[string]string{
				"MCP_TRANSPORT":           "http",
				"MCP_ALLOW_INSECURE_HTTP": "true",
				"MCP_HTTP_PATH":           "mcp",
			},
			wantErr: "MCP_HTTP_PATH",
		},
		{
			name:    "empty server name",
			env:     map[string]string{"MCP_SERVER_NAME": " "},
			wantErr: "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			_, err := Load()
			if tc.wantErr == "" {
				return // this case only asserts Load does not panic
			}
			if err == nil {
				t.Fatalf("Load accepted an invalid configuration")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}

func TestRedactedHidesSecrets(t *testing.T) {
	t.Setenv("BACKEND_API_TOKEN", "sk-live-should-never-be-logged")
	t.Setenv("MCP_HTTP_BEARER_TOKEN", "bearer-should-never-be-logged")
	t.Setenv("CURSOR_SECRET", "cursor-should-never-be-logged")
	t.Setenv("MCP_OAUTH_HMAC_SECRET", "hmac-should-never-be-logged-0123456789")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	redacted := cfg.Redacted()
	for k, v := range redacted {
		if s, ok := v.(string); ok && strings.Contains(s, "should-never-be-logged") {
			t.Fatalf("Redacted()[%q] leaks a secret: %q", k, s)
		}
	}
	// Presence must still be reportable, so a misconfiguration is diagnosable.
	if redacted["backend_token"] != "set" || redacted["auth_static_token"] != "set" {
		t.Errorf("Redacted() should report configured secrets as set, got %v", redacted)
	}
}

func TestParseLevel(t *testing.T) {
	tests := map[string]slog.Level{
		"debug":    slog.LevelDebug,
		"INFO":     slog.LevelInfo,
		"warn":     slog.LevelWarn,
		"warning":  slog.LevelWarn,
		"error":    slog.LevelError,
		"nonsense": slog.LevelInfo,
		"":         slog.LevelInfo,
	}
	for in, want := range tests {
		if got := parseLevel(in); got != want {
			t.Errorf("parseLevel(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestRedactedOmitsHTTPSettingsUnderStdio(t *testing.T) {
	// Reporting http_addr when the stdio transport is selected says a port is
	// in play when none is. An operator reads it as "the server is listening
	// there" and goes hunting for a socket that was never opened.
	t.Setenv("MCP_TRANSPORT", "stdio")
	t.Setenv("MCP_HTTP_ADDR", "127.0.0.1:8080")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	redacted := cfg.Redacted()

	for _, key := range []string{"http_addr", "http_path", "http_stateless", "http_json_response", "metrics_path"} {
		if v, present := redacted[key]; present {
			t.Errorf("Redacted()[%q] = %v under the stdio transport; no HTTP server will start", key, v)
		}
	}
	if redacted["transport"] != "stdio" {
		t.Errorf("transport = %v, want stdio", redacted["transport"])
	}
	// Secret presence is still reported regardless of transport: an operator
	// wants to know a token is set even when it is unused.
	if _, present := redacted["backend_token"]; !present {
		t.Error("backend_token is missing; secret presence must always be reportable")
	}
}

func TestRedactedIncludesHTTPSettingsUnderHTTP(t *testing.T) {
	t.Setenv("MCP_TRANSPORT", "http")
	t.Setenv("MCP_ALLOW_INSECURE_HTTP", "true")
	t.Setenv("MCP_HTTP_ADDR", "127.0.0.1:9191")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	redacted := cfg.Redacted()

	if redacted["http_addr"] != "127.0.0.1:9191" {
		t.Errorf("http_addr = %v, want the configured address", redacted["http_addr"])
	}
	for _, key := range []string{"http_path", "http_stateless", "http_json_response", "metrics_path"} {
		if _, present := redacted[key]; !present {
			t.Errorf("Redacted() is missing %q under the HTTP transport", key)
		}
	}
}
