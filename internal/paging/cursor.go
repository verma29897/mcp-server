// Package paging encodes and verifies opaque pagination cursors.
//
// A cursor is a capability, not a bookmark. If a client can construct or edit
// one, it can page through a listing it was never authorized to see, or resume
// another tenant's listing by swapping an id. So a cursor here is
// HMAC-authenticated and bound to the exact query it belongs to: the tenant,
// the principal, the operation and a hash of the filters. Changing any of those
// invalidates it.
//
// The cursor is not encrypted, only authenticated. It carries no secret - the
// resume key is an identifier the caller has already seen - so integrity is the
// property that matters, and an authenticated cursor is cheaper and easier to
// reason about than an encrypted one.
package paging

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrInvalidCursor reports a cursor that failed verification. Like an invalid
// token, it is undifferentiated on purpose: forged, expired, edited and
// belonging-to-another-query all look identical to the caller.
var ErrInvalidCursor = errors.New("cursor is not valid for this query")

// TTL bounds how long a cursor stays usable. A listing resumed a day later is
// answering a question about a dataset that has moved on; expiring the cursor
// makes the client restart rather than silently skip records.
const TTL = 15 * time.Minute

// payload is the authenticated body of a cursor.
type payload struct {
	// V is the format version, so the encoding can change without accepting
	// ambiguous old cursors.
	V int `json:"v"`
	// After is the sort key to resume after.
	After string `json:"a"`
	// Bind is the hash of tenant + principal + operation + filters.
	Bind string `json:"b"`
	// Exp is the expiry, as a Unix timestamp.
	Exp int64 `json:"e"`
}

const version = 1

// Codec signs and verifies cursors with a process secret.
type Codec struct {
	secret []byte
	now    func() time.Time
}

// NewCodec returns a codec keyed by secret.
//
// An empty secret makes the codec generate a random one at start. That is the
// right default for a single replica and the wrong one for several: a cursor
// issued by one replica will not verify on another, so the client sees its
// pagination break at random. Multi-replica deployments must configure a shared
// secret, and config validation says so.
func NewCodec(secret string) *Codec {
	key := []byte(secret)
	if len(key) == 0 {
		key = make([]byte, 32)
		_, _ = rand.Read(key)
	}
	// Fold whatever length was supplied into a fixed-size key.
	sum := sha256.Sum256(key)
	return &Codec{secret: sum[:], now: time.Now}
}

// Binding describes the query a cursor belongs to.
type Binding struct {
	Tenant    string
	Principal string
	Operation string
	// Filters is the canonical rendering of everything that shapes the result
	// set. Two queries with different filters must produce different strings.
	Filters string
}

func (b Binding) hash() string {
	h := sha256.New()
	for _, part := range []string{b.Tenant, b.Principal, b.Operation, b.Filters} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil)[:16])
}

// Encode produces a cursor resuming after the given sort key.
//
// An empty key yields an empty cursor: there is no next page, and emitting a
// cursor that leads nowhere invites a client to loop.
func (c *Codec) Encode(b Binding, after string) string {
	if after == "" {
		return ""
	}
	body, err := json.Marshal(payload{
		V:     version,
		After: after,
		Bind:  b.hash(),
		Exp:   c.now().Add(TTL).Unix(),
	})
	if err != nil {
		return ""
	}
	encoded := base64.RawURLEncoding.EncodeToString(body)
	return encoded + "." + c.sign(encoded)
}

// Decode verifies a cursor against its binding and returns the resume key.
func (c *Codec) Decode(b Binding, cursor string) (string, error) {
	cursor = strings.TrimSpace(cursor)
	if cursor == "" {
		return "", nil
	}
	// A bounded length before any parsing: a cursor is ~120 bytes, and an
	// attacker should not be able to make the server base64-decode a megabyte.
	if len(cursor) > 1024 {
		return "", ErrInvalidCursor
	}

	encoded, sig, ok := strings.Cut(cursor, ".")
	if !ok {
		return "", ErrInvalidCursor
	}
	// Constant time: the signature is the only thing standing between a caller
	// and a forged cursor.
	if !hmac.Equal([]byte(sig), []byte(c.sign(encoded))) {
		return "", ErrInvalidCursor
	}

	body, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return "", ErrInvalidCursor
	}
	var p payload
	if err := json.Unmarshal(body, &p); err != nil {
		return "", ErrInvalidCursor
	}
	if p.V != version {
		return "", ErrInvalidCursor
	}
	if p.Bind != b.hash() {
		// The cursor is authentic but belongs to a different tenant,
		// principal, operation or filter set. This is the check that stops a
		// cursor being replayed across an authorization boundary.
		return "", ErrInvalidCursor
	}
	if c.now().Unix() > p.Exp {
		return "", fmt.Errorf("%w: expired", ErrInvalidCursor)
	}
	return p.After, nil
}

func (c *Codec) sign(encoded string) string {
	mac := hmac.New(sha256.New, c.secret)
	mac.Write([]byte(encoded))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
