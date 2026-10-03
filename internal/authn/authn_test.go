package authn

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/verma29897/mcp-server/internal/authz"
)

const (
	testIssuer   = "https://idp.example/"
	testAudience = "https://mcp.example/mcp"
	testHMAC     = "an-hmac-secret-of-at-least-32-characters"
)

func TestStaticVerifierIsConstantTimeAndFixed(t *testing.T) {
	v, err := NewStatic("a-sufficiently-long-token", "svc", "acme", authz.ReadOnlyScopes)
	if err != nil {
		t.Fatalf("NewStatic: %v", err)
	}

	p, err := v.Verify(context.Background(), "a-sufficiently-long-token")
	if err != nil {
		t.Fatalf("Verify with the correct token: %v", err)
	}
	if p.TenantID != "acme" || p.Mode != authz.AuthStatic {
		t.Errorf("principal = %+v, want the configured tenant and static mode", p)
	}
	if p.Has(authz.ScopeCustomerDelete) {
		t.Error("the static principal holds a scope it was not granted")
	}

	for _, bad := range []string{"", "a-sufficiently-long-toke", "a-sufficiently-long-tokenX", "wrong"} {
		if _, err := v.Verify(context.Background(), bad); !errors.Is(err, ErrInvalidToken) {
			t.Errorf("Verify(%q) = %v, want ErrInvalidToken", bad, err)
		}
	}
}

func TestNewStaticRejectsWeakConfiguration(t *testing.T) {
	tests := []struct {
		name                   string
		token, subject, tenant string
	}{
		{"empty token", "", "svc", "acme"},
		{"short token", "too-short", "svc", "acme"},
		{"no tenant", "a-sufficiently-long-token", "svc", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewStatic(tc.token, tc.subject, tc.tenant, nil); err == nil {
				t.Fatal("NewStatic accepted a configuration it should refuse")
			}
		})
	}
}

// signHS produces a token signed with the shared HMAC secret.
func signHS(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	s, err := tok.SignedString([]byte(testHMAC))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

func validClaims() jwt.MapClaims {
	now := time.Now()
	return jwt.MapClaims{
		"iss":       testIssuer,
		"aud":       testAudience,
		"sub":       "user-42",
		"exp":       now.Add(time.Hour).Unix(),
		"iat":       now.Unix(),
		"tenant_id": "acme",
		"scope":     "customer:read customer:search",
		"client_id": "claude-desktop",
	}
}

func newHMACVerifier(t *testing.T) *JWTVerifier {
	t.Helper()
	v, err := NewJWT(JWTConfig{
		Issuer:     testIssuer,
		Audience:   testAudience,
		HMACSecret: testHMAC,
	}, nil)
	if err != nil {
		t.Fatalf("NewJWT: %v", err)
	}
	return v
}

func TestJWTVerifierAcceptsAWellFormedToken(t *testing.T) {
	v := newHMACVerifier(t)

	p, err := v.Verify(context.Background(), signHS(t, validClaims()))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if p.Subject != "user-42" || p.TenantID != "acme" || p.ClientID != "claude-desktop" {
		t.Errorf("principal = %+v, want the claims from the token", p)
	}
	if !p.Has(authz.ScopeCustomerRead) || !p.Has(authz.ScopeCustomerSearch) {
		t.Errorf("scopes = %v, want the two granted scopes", p.Scopes)
	}
	if p.Has(authz.ScopeCustomerDelete) {
		t.Error("a scope not present in the token was granted")
	}
	if p.ExpiresAt.IsZero() {
		t.Error("the principal carries no expiry")
	}
}

func TestJWTVerifierRejectsBadTokens(t *testing.T) {
	v := newHMACVerifier(t)

	mutate := func(f func(jwt.MapClaims)) string {
		c := validClaims()
		f(c)
		return signHS(t, c)
	}

	tests := []struct {
		name  string
		token string
	}{
		{"wrong issuer", mutate(func(c jwt.MapClaims) { c["iss"] = "https://evil.example/" })},
		{"wrong audience", mutate(func(c jwt.MapClaims) { c["aud"] = "https://other-service.example" })},
		{"expired", mutate(func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-2 * time.Hour).Unix() })},
		{"not yet valid", mutate(func(c jwt.MapClaims) { c["nbf"] = time.Now().Add(2 * time.Hour).Unix() })},
		{"no expiry at all", mutate(func(c jwt.MapClaims) { delete(c, "exp") })},
		{"no subject", mutate(func(c jwt.MapClaims) { delete(c, "sub") })},
		{"no tenant", mutate(func(c jwt.MapClaims) { delete(c, "tenant_id") })},
		{"empty", ""},
		{"garbage", "not.a.token"},
		{"truncated", signHS(t, validClaims())[:20]},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := v.Verify(context.Background(), tc.token); !errors.Is(err, ErrInvalidToken) {
				t.Fatalf("Verify accepted %s: %v", tc.name, err)
			}
		})
	}
}

func TestJWTVerifierRejectsAlgorithmConfusion(t *testing.T) {
	// The classic attack: take a server that verifies RS256, hand it a token
	// signed HS256 with the public key as the secret. Pinning the algorithm
	// list is what stops it, so the test pins the behaviour.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	jwks := newJWKSServer(t, key)

	v, err := NewJWT(JWTConfig{
		Issuer:   testIssuer,
		Audience: testAudience,
		JWKSURL:  jwks.URL,
	}, NewKeySet(jwks.URL, jwks.Client(), time.Minute))
	if err != nil {
		t.Fatalf("NewJWT: %v", err)
	}

	t.Run("HS256 against an RSA verifier", func(t *testing.T) {
		tok := jwt.NewWithClaims(jwt.SigningMethodHS256, validClaims())
		tok.Header["kid"] = "test-key"
		signed, err := tok.SignedString([]byte("anything"))
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		if _, err := v.Verify(context.Background(), signed); !errors.Is(err, ErrInvalidToken) {
			t.Fatal("an HS256 token was accepted by an RSA verifier")
		}
	})

	t.Run("alg none", func(t *testing.T) {
		tok := jwt.NewWithClaims(jwt.SigningMethodNone, validClaims())
		tok.Header["kid"] = "test-key"
		signed, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		if _, err := v.Verify(context.Background(), signed); !errors.Is(err, ErrInvalidToken) {
			t.Fatal("an unsigned token was accepted")
		}
	})

	t.Run("valid RS256 is accepted", func(t *testing.T) {
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, validClaims())
		tok.Header["kid"] = "test-key"
		signed, err := tok.SignedString(key)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		p, err := v.Verify(context.Background(), signed)
		if err != nil {
			t.Fatalf("a correctly signed RS256 token was refused: %v", err)
		}
		if p.Subject != "user-42" {
			t.Errorf("subject = %q, want user-42", p.Subject)
		}
	})

	t.Run("signed by the wrong key", func(t *testing.T) {
		other, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, validClaims())
		tok.Header["kid"] = "test-key"
		signed, err := tok.SignedString(other)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		if _, err := v.Verify(context.Background(), signed); !errors.Is(err, ErrInvalidToken) {
			t.Fatal("a token signed by an unknown key was accepted")
		}
	})
}

func TestJWTVerifierReadsScopesFromEitherClaimShape(t *testing.T) {
	v := newHMACVerifier(t)

	t.Run("space-delimited scope string", func(t *testing.T) {
		c := validClaims()
		c["scope"] = "customer:read notification:send"
		p, err := v.Verify(context.Background(), signHS(t, c))
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if !p.Has(authz.ScopeNotificationSend) {
			t.Errorf("scopes = %v, want the scope claim honoured", p.Scopes)
		}
	})

	t.Run("array in permissions", func(t *testing.T) {
		c := validClaims()
		delete(c, "scope")
		c["permissions"] = []any{"customer:read", "customer:delete"}
		p, err := v.Verify(context.Background(), signHS(t, c))
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if !p.Has(authz.ScopeCustomerDelete) {
			t.Errorf("scopes = %v, want the permissions claim honoured", p.Scopes)
		}
	})

	t.Run("no scopes at all grants nothing", func(t *testing.T) {
		c := validClaims()
		delete(c, "scope")
		p, err := v.Verify(context.Background(), signHS(t, c))
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		for _, s := range authz.AllScopes {
			if p.Has(s) {
				t.Errorf("a token with no scope claim granted %q", s)
			}
		}
	})
}

func TestJWTVerifierEnforcesRequiredScopes(t *testing.T) {
	v, err := NewJWT(JWTConfig{
		Issuer:         testIssuer,
		Audience:       testAudience,
		HMACSecret:     testHMAC,
		RequiredScopes: []string{"mcp:connect"},
	}, nil)
	if err != nil {
		t.Fatalf("NewJWT: %v", err)
	}

	if _, err := v.Verify(context.Background(), signHS(t, validClaims())); !errors.Is(err, ErrInvalidToken) {
		t.Fatal("a token missing a required scope was accepted")
	}

	c := validClaims()
	c["scope"] = "mcp:connect customer:read"
	if _, err := v.Verify(context.Background(), signHS(t, c)); err != nil {
		t.Fatalf("a token carrying the required scope was refused: %v", err)
	}
}

func TestNewJWTRefusesUnsafeConfiguration(t *testing.T) {
	tests := []struct {
		name string
		cfg  JWTConfig
	}{
		{"no issuer", JWTConfig{Audience: testAudience, HMACSecret: testHMAC}},
		// Without an audience, a token minted for any other service by the same
		// issuer would be replayable here.
		{"no audience", JWTConfig{Issuer: testIssuer, HMACSecret: testHMAC}},
		{"no key material", JWTConfig{Issuer: testIssuer, Audience: testAudience}},
		{"both key kinds", JWTConfig{Issuer: testIssuer, Audience: testAudience, HMACSecret: testHMAC, JWKSURL: "https://idp.example/jwks"}},
		{"weak hmac secret", JWTConfig{Issuer: testIssuer, Audience: testAudience, HMACSecret: "short"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewJWT(tc.cfg, nil); err == nil {
				t.Fatal("NewJWT accepted a configuration it should refuse")
			}
		})
	}
}

func TestVerificationErrorsCarryNoTokenMaterial(t *testing.T) {
	v := newHMACVerifier(t)
	const secretish = "eyJhbGciOiJIUzI1NiJ9.super-secret-payload.sig"

	_, err := v.Verify(context.Background(), secretish)
	if err == nil {
		t.Fatal("expected a rejection")
	}
	if strings.Contains(err.Error(), "super-secret-payload") {
		t.Errorf("the verification error echoes the token: %q", err)
	}
}

// newJWKSServer serves a JWKS containing key's public half.
func newJWKSServer(t *testing.T, key *rsa.PrivateKey) *httptest.Server {
	t.Helper()
	doc := map[string]any{
		"keys": []map[string]string{{
			"kty": "RSA",
			"kid": "test-key",
			"use": "sig",
			"alg": "RS256",
			"n":   base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
		}},
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	}))
	t.Cleanup(ts.Close)
	return ts
}

func TestKeySetSurvivesAnUnreachableIssuer(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	var fail bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if fail {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{{
				"kty": "RSA", "kid": "k1", "use": "sig", "alg": "RS256",
				"n": base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
			}},
		})
	}))
	defer ts.Close()

	// A one-nanosecond refresh interval means every lookup revalidates, which
	// is how the test forces the failure path without waiting.
	ks := NewKeySet(ts.URL, ts.Client(), time.Nanosecond)
	ks.minRefreshGap = 0

	if _, err := ks.key(context.Background(), "k1", "RS256"); err != nil {
		t.Fatalf("first lookup: %v", err)
	}

	fail = true
	// The provider is down. Serving the cached key is the right answer: the
	// alternative is refusing every request while an unrelated service is out.
	if _, err := ks.key(context.Background(), "k1", "RS256"); err != nil {
		t.Errorf("a cached key was discarded when the issuer became unreachable: %v", err)
	}
	// An unknown kid still fails, because there is nothing to serve.
	if _, err := ks.key(context.Background(), "unknown", "RS256"); err == nil {
		t.Error("an unknown kid resolved to a key")
	}
}

func TestKeySetAcceptsAnECKeyAndRejectsAnOffCurvePoint(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	enc := func(i *big.Int) string {
		b := make([]byte, 32)
		i.FillBytes(b)
		return base64.RawURLEncoding.EncodeToString(b)
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{
				{"kty": "EC", "kid": "ec-good", "use": "sig", "alg": "ES256", "crv": "P-256",
					"x": enc(key.PublicKey.X), "y": enc(key.PublicKey.Y)},
				// Same x, a y that does not satisfy the curve equation. Accepting
				// it is the invalid-curve attack, which recovers the private key
				// of whoever signs against it.
				{"kty": "EC", "kid": "ec-bad", "use": "sig", "alg": "ES256", "crv": "P-256",
					"x": enc(key.PublicKey.X), "y": enc(new(big.Int).Add(key.PublicKey.Y, big.NewInt(1)))},
			},
		})
	}))
	defer ts.Close()

	ks := NewKeySet(ts.URL, ts.Client(), time.Minute)
	if _, err := ks.key(context.Background(), "ec-good", "ES256"); err != nil {
		t.Errorf("a valid EC key was rejected: %v", err)
	}
	if _, err := ks.key(context.Background(), "ec-bad", "ES256"); err == nil {
		t.Error("an off-curve EC point was accepted")
	}

	v, err := NewJWT(JWTConfig{Issuer: testIssuer, Audience: testAudience, JWKSURL: ts.URL}, ks)
	if err != nil {
		t.Fatalf("NewJWT: %v", err)
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, validClaims())
	tok.Header["kid"] = "ec-good"
	signed, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := v.Verify(context.Background(), signed); err != nil {
		t.Errorf("a correctly signed ES256 token was refused: %v", err)
	}
}

func TestKeySetRejectsWeakAndMalformedKeys(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{
				// 512-bit modulus: below the RFC 7518 floor for RS256.
				{"kty": "RSA", "kid": "weak", "n": base64.RawURLEncoding.EncodeToString(make([]byte, 64)), "e": "AQAB"},
				{"kty": "RSA", "kid": "malformed", "n": "!!!not-base64!!!", "e": "AQAB"},
				{"kty": "OKP", "kid": "unsupported", "crv": "Ed25519", "x": "abc"},
			},
		})
	}))
	defer ts.Close()

	ks := NewKeySet(ts.URL, ts.Client(), time.Minute)
	for _, kid := range []string{"weak", "malformed", "unsupported"} {
		if _, err := ks.key(context.Background(), kid, "RS256"); err == nil {
			t.Errorf("key %q was accepted", kid)
		}
	}
}
