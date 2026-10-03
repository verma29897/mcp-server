package config

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
)

// .env loading, with one rule that matters more than the rest:
//
//	A value already present in the real environment is NEVER overridden.
//
// The file fills gaps; it does not win arguments. That direction is what makes
// the feature safe to ship in a server that handles customer data. An .env that
// could override the environment would mean a stray file baked into a container
// image silently replacing what the orchestrator injected - and the failure
// would be invisible, because the process would start happily with the wrong
// backend, the wrong tenant or the wrong token.
//
// It is a development convenience with a production-safe precedence, not a
// configuration mechanism. Secrets in production still come from a secret
// manager through the environment.

// DefaultEnvFile is the file consulted when none is named.
const DefaultEnvFile = ".env"

// maxEnvFileBytes bounds the file. A .env is a few kilobytes; anything larger
// is a mistake, and reading it into memory unbounded is a needless risk.
const maxEnvFileBytes = 1 << 20

// EnvFileResult reports what LoadEnvFile did, for a startup log line.
type EnvFileResult struct {
	// Path is the file that was read. Empty when none was found.
	Path string
	// Applied counts values taken from the file.
	Applied int
	// Skipped counts values the file defined that the environment already had.
	Skipped []string
}

// LoadEnvFile reads path and sets any variable not already in the environment.
//
// A missing file is not an error: the server must start with no .env at all,
// which is exactly what a production deployment does. A malformed file IS an
// error, because silently ignoring a line the operator believed was setting a
// token is the failure this whole package exists to prevent.
func LoadEnvFile(path string) (EnvFileResult, error) {
	if path == "" {
		path = DefaultEnvFile
	}

	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return EnvFileResult{}, nil
		}
		return EnvFileResult{}, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return EnvFileResult{}, fmt.Errorf("stat %s: %w", path, err)
	}
	if info.IsDir() {
		return EnvFileResult{}, fmt.Errorf("%s is a directory", path)
	}
	if info.Size() > maxEnvFileBytes {
		return EnvFileResult{}, fmt.Errorf("%s is %d bytes, over the %d byte limit", path, info.Size(), maxEnvFileBytes)
	}

	result := EnvFileResult{Path: path}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), maxEnvFileBytes)

	for line := 1; scanner.Scan(); line++ {
		key, value, ok, err := parseEnvLine(scanner.Text())
		if err != nil {
			return EnvFileResult{}, fmt.Errorf("%s:%d: %w", path, line, err)
		}
		if !ok {
			continue // blank or comment
		}
		if _, present := os.LookupEnv(key); present {
			result.Skipped = append(result.Skipped, key)
			continue
		}
		if err := os.Setenv(key, value); err != nil {
			return EnvFileResult{}, fmt.Errorf("%s:%d: set %s: %w", path, line, key, err)
		}
		result.Applied++
	}
	if err := scanner.Err(); err != nil {
		return EnvFileResult{}, fmt.Errorf("read %s: %w", path, err)
	}
	return result, nil
}

// parseEnvLine parses one line into a key and value.
//
// Supported, because these are what people actually write:
//
//	KEY=value
//	KEY = value            surrounding space trimmed
//	export KEY=value       so a file can also be `source`d
//	KEY="value with #"     double quotes; \n \t \\ \" unescaped
//	KEY='value as-is'      single quotes; nothing unescaped
//	KEY=                   an explicit empty value
//	# comment              ignored
//	KEY=value # trailing   comment stripped, unquoted values only
//
// Deliberately not supported: variable interpolation (`KEY=$OTHER`) and command
// substitution. Both invite a config file to depend on evaluation order or to
// execute something, and neither is worth the surprise in a file that carries
// credentials.
func parseEnvLine(raw string) (key, value string, ok bool, err error) {
	line := strings.TrimSpace(raw)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", "", false, nil
	}
	line = strings.TrimPrefix(line, "export ")

	name, rest, found := strings.Cut(line, "=")
	if !found {
		return "", "", false, fmt.Errorf("expected KEY=VALUE, got %q", truncateLine(raw))
	}
	key = strings.TrimSpace(name)
	if err := validateEnvKey(key); err != nil {
		return "", "", false, err
	}

	rest = strings.TrimSpace(rest)
	switch {
	case strings.HasPrefix(rest, `"`):
		value, err = unquote(rest, '"', true)
	case strings.HasPrefix(rest, `'`):
		value, err = unquote(rest, '\'', false)
	default:
		// An unquoted value ends at an unescaped ' #'. Requiring the space
		// means a value that legitimately contains '#' - a URL fragment, a
		// generated password - is not silently truncated.
		if i := strings.Index(rest, " #"); i >= 0 {
			rest = rest[:i]
		}
		value = strings.TrimSpace(rest)
	}
	if err != nil {
		return "", "", false, err
	}
	return key, value, true, nil
}

// unquote reads a quoted value, optionally processing escapes.
func unquote(s string, quote byte, escapes bool) (string, error) {
	var b strings.Builder
	for i := 1; i < len(s); i++ {
		c := s[i]
		if escapes && c == '\\' && i+1 < len(s) {
			i++
			switch s[i] {
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case 'r':
				b.WriteByte('\r')
			case '\\':
				b.WriteByte('\\')
			case quote:
				b.WriteByte(quote)
			default:
				b.WriteByte('\\')
				b.WriteByte(s[i])
			}
			continue
		}
		if c == quote {
			return b.String(), nil
		}
		b.WriteByte(c)
	}
	return "", fmt.Errorf("unterminated %c quote", quote)
}

// validateEnvKey rejects a name that is not a shell-safe identifier.
//
// The narrow character class is not pedantry: a key with a space or a quote in
// it is almost always a typo in a line the operator believed was setting a
// credential, and failing loudly beats starting with that credential unset.
func validateEnvKey(key string) error {
	if key == "" {
		return errors.New("empty variable name")
	}
	if key[0] >= '0' && key[0] <= '9' {
		return fmt.Errorf("variable name %q starts with a digit", key)
	}
	for i := 0; i < len(key); i++ {
		c := key[i]
		ok := c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_'
		if !ok {
			return fmt.Errorf("variable name %q contains %q; use letters, digits and underscore", key, string(c))
		}
	}
	return nil
}

func truncateLine(s string) string {
	const max = 60
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
