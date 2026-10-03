package authn

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// KeySet is a caching JWKS client.
//
// Two properties matter for production. First, a key rotation must not cause an
// outage: an unknown `kid` triggers one refresh, rate-limited so a flood of
// bogus tokens cannot turn into a flood of requests at the identity provider.
// Second, a temporarily unreachable provider must not cause an outage either:
// the last good key set is kept and served past its refresh interval rather
// than being discarded.
type KeySet struct {
	url    string
	client *http.Client

	// refreshInterval is how long a fetched set is served without revalidating.
	refreshInterval time.Duration
	// minRefreshGap rate-limits forced refreshes triggered by an unknown kid.
	minRefreshGap time.Duration

	mu          sync.RWMutex
	keys        map[string]any
	fetchedAt   time.Time
	lastAttempt time.Time
	// single ensures concurrent misses collapse into one upstream fetch.
	single sync.Mutex
}

// maxJWKSBytes bounds a JWKS response. A key set is a few kilobytes; anything
// larger is either a misconfiguration or an attempt to exhaust memory.
const maxJWKSBytes = 1 << 20

// NewKeySet returns a caching JWKS client for url.
func NewKeySet(url string, client *http.Client, refresh time.Duration) *KeySet {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	if refresh <= 0 {
		refresh = 15 * time.Minute
	}
	return &KeySet{
		url:             url,
		client:          client,
		refreshInterval: refresh,
		minRefreshGap:   time.Minute,
		keys:            map[string]any{},
	}
}

// key returns the public key for kid, fetching or refreshing as needed.
func (k *KeySet) key(ctx context.Context, kid, alg string) (any, error) {
	if key, fresh := k.cached(kid); key != nil && fresh {
		return key, nil
	}

	if err := k.refresh(ctx); err != nil {
		// A refresh failure is survivable when a cached key still answers: the
		// alternative is refusing every request while the provider is down.
		if key, _ := k.cached(kid); key != nil {
			return key, nil
		}
		return nil, fmt.Errorf("fetch signing keys: %w", err)
	}

	if key, _ := k.cached(kid); key != nil {
		return key, nil
	}
	if kid == "" {
		// A token with no kid is only unambiguous when the set has one key.
		k.mu.RLock()
		defer k.mu.RUnlock()
		if len(k.keys) == 1 {
			for _, key := range k.keys {
				return key, nil
			}
		}
		return nil, errors.New("token has no kid and the key set is ambiguous")
	}
	return nil, fmt.Errorf("no signing key for kid %q (alg %s)", kid, alg)
}

func (k *KeySet) cached(kid string) (any, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	fresh := time.Since(k.fetchedAt) < k.refreshInterval
	if kid == "" && len(k.keys) == 1 {
		for _, key := range k.keys {
			return key, fresh
		}
	}
	return k.keys[kid], fresh
}

// refresh fetches the key set, collapsing concurrent callers onto one request.
func (k *KeySet) refresh(ctx context.Context) error {
	k.single.Lock()
	defer k.single.Unlock()

	k.mu.RLock()
	fresh := time.Since(k.fetchedAt) < k.refreshInterval
	throttled := time.Since(k.lastAttempt) < k.minRefreshGap
	k.mu.RUnlock()
	if fresh {
		return nil // another goroutine refreshed while we waited for the lock
	}
	if throttled {
		return errors.New("jwks refresh throttled")
	}

	k.mu.Lock()
	k.lastAttempt = time.Now()
	k.mu.Unlock()

	keys, err := k.fetch(ctx)
	if err != nil {
		return err
	}

	k.mu.Lock()
	k.keys = keys
	k.fetchedAt = time.Now()
	k.mu.Unlock()
	return nil
}

func (k *KeySet) fetch(ctx context.Context) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := k.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks endpoint returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes))
	if err != nil {
		return nil, err
	}

	var doc struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("decode jwks: %w", err)
	}

	out := make(map[string]any, len(doc.Keys))
	for _, key := range doc.Keys {
		// "sig" or unset; an encryption key must not verify a signature.
		if key.Use != "" && key.Use != "sig" {
			continue
		}
		pub, err := key.public()
		if err != nil {
			continue // one malformed key must not invalidate the whole set
		}
		out[key.Kid] = pub
	}
	if len(out) == 0 {
		return nil, errors.New("jwks contained no usable signing key")
	}
	return out, nil
}

// jwk is one JSON Web Key (RFC 7517) in the subset this server verifies.
type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func (k jwk) public() (any, error) {
	switch strings.ToUpper(k.Kty) {
	case "RSA":
		return k.rsa()
	case "EC":
		return k.ecdsa()
	default:
		return nil, fmt.Errorf("unsupported key type %q", k.Kty)
	}
}

func (k jwk) rsa() (*rsa.PublicKey, error) {
	n, err := b64uint(k.N)
	if err != nil {
		return nil, err
	}
	e, err := b64uint(k.E)
	if err != nil {
		return nil, err
	}
	if !e.IsInt64() || e.Int64() <= 0 || e.Int64() > 1<<31-1 {
		return nil, errors.New("rsa exponent out of range")
	}
	// 2048 bits is the floor RFC 7518 requires for RS256.
	if n.BitLen() < 2048 {
		return nil, fmt.Errorf("rsa modulus is %d bits, want at least 2048", n.BitLen())
	}
	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}

func (k jwk) ecdsa() (*ecdsa.PublicKey, error) {
	var (
		curve     elliptic.Curve
		ecdhCurve ecdh.Curve
		size      int
	)
	switch k.Crv {
	case "P-256":
		curve, ecdhCurve, size = elliptic.P256(), ecdh.P256(), 32
	case "P-384":
		curve, ecdhCurve, size = elliptic.P384(), ecdh.P384(), 48
	case "P-521":
		curve, ecdhCurve, size = elliptic.P521(), ecdh.P521(), 66
	default:
		return nil, fmt.Errorf("unsupported curve %q", k.Crv)
	}

	x, err := b64uint(k.X)
	if err != nil {
		return nil, err
	}
	y, err := b64uint(k.Y)
	if err != nil {
		return nil, err
	}

	// Validate through crypto/ecdh rather than elliptic.IsOnCurve, which is
	// deprecated and documented as a low-level unsafe API. NewPublicKey
	// performs the on-curve and point-at-infinity checks; accepting a point off
	// the curve is the invalid-curve attack, and it recovers the private key of
	// whoever signs with it.
	point := make([]byte, 1+2*size)
	point[0] = 4 // uncompressed
	x.FillBytes(point[1 : 1+size])
	y.FillBytes(point[1+size:])
	if _, err := ecdhCurve.NewPublicKey(point); err != nil {
		return nil, fmt.Errorf("ec point is not valid for %s: %w", k.Crv, err)
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

// b64uint decodes a base64url big-endian unsigned integer (RFC 7518 §2).
func b64uint(s string) (*big.Int, error) {
	if s == "" {
		return nil, errors.New("empty key parameter")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
	if err != nil {
		return nil, fmt.Errorf("decode key parameter: %w", err)
	}
	return new(big.Int).SetBytes(raw), nil
}
