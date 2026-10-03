// Package idempotency makes a side-effecting operation safe to retry.
//
// The problem it solves is concrete. send_customer_notification contacts a real
// person. A model that does not see a response - because the connection
// dropped, because the client timed out, because the model simply decided to
// try again - will call it a second time, and the customer receives the message
// twice. Nothing in MCP prevents that, and no amount of tool description
// prevents it either, because the retry is a client decision.
//
// The contract:
//
//	key absent          the call executes normally, no record is kept
//	key first seen      the call executes; the receipt is stored under the key
//	key seen, same args the stored receipt is replayed; nothing is sent
//	key seen, other args CONFLICT - the same key must not mean two things
//	key in flight       CONFLICT - a concurrent duplicate is refused, not queued
//
// Records expire. A key is a promise that a retry within the window is safe,
// not a permanent ledger.
package idempotency

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"
)

// ErrInFlight reports that another request is already executing under this key.
var ErrInFlight = errors.New("idempotency: a request with this key is in flight")

// ErrMismatch reports that the key was previously used with different
// arguments.
var ErrMismatch = errors.New("idempotency: key was already used with different arguments")

// Record is a completed operation held against its key.
type Record struct {
	// Fingerprint identifies the arguments the key was first used with.
	Fingerprint string
	// Payload is the stored result, as JSON.
	Payload []byte
	// StoredAt is when the operation completed.
	StoredAt time.Time
}

// Store holds idempotency records.
//
// The interface exists so a horizontally scaled deployment can substitute a
// shared implementation. The in-memory store below is correct for a single
// replica and honest about that: with several replicas behind a load balancer,
// a retry that lands on another replica finds no record and the message is sent
// twice. See docs/DEPLOYMENT.md.
type Store interface {
	// Begin reserves key for an operation with the given fingerprint.
	//
	// It returns a replayable record when the operation has already completed
	// with a matching fingerprint, ErrMismatch when the fingerprint differs,
	// and ErrInFlight when another caller holds the reservation.
	Begin(ctx context.Context, key, fingerprint string) (*Record, error)
	// Commit stores the result of a reserved key.
	Commit(ctx context.Context, key string, payload []byte) error
	// Abort releases a reservation whose operation failed, so a retry may
	// proceed. A failed send must not poison the key.
	Abort(ctx context.Context, key string)
}

// Key length bounds. Long enough for a UUID or a hash, short enough that a key
// cannot be used as a storage channel; long enough at the bottom that a key is
// unguessable by a caller trying to collide with someone else's.
const (
	MinKeyLength = 8
	MaxKeyLength = 128
)

// Memory is an in-process Store with TTL expiry.
type Memory struct {
	ttl time.Duration
	// maxEntries bounds memory. When exceeded, the oldest entries are dropped:
	// losing an old record degrades to "the message may be sent twice", which
	// is strictly better than an unbounded map.
	maxEntries int

	mu      sync.Mutex
	entries map[string]*entry
	now     func() time.Time
}

type entry struct {
	fingerprint string
	payload     []byte
	inFlight    bool
	at          time.Time
}

var _ Store = (*Memory)(nil)

// NewMemory returns an in-process store. A ttl of zero uses 24 hours.
func NewMemory(ttl time.Duration, maxEntries int) *Memory {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	if maxEntries <= 0 {
		maxEntries = 100_000
	}
	return &Memory{
		ttl:        ttl,
		maxEntries: maxEntries,
		entries:    map[string]*entry{},
		now:        time.Now,
	}
}

// Begin implements Store.
func (m *Memory) Begin(_ context.Context, key, fingerprint string) (*Record, error) {
	now := m.now()

	m.mu.Lock()
	defer m.mu.Unlock()
	m.expireLocked(now)

	e, ok := m.entries[key]
	switch {
	case !ok:
		m.evictLocked()
		m.entries[key] = &entry{fingerprint: fingerprint, inFlight: true, at: now}
		return nil, nil
	case e.fingerprint != fingerprint:
		return nil, ErrMismatch
	case e.inFlight:
		return nil, ErrInFlight
	default:
		return &Record{
			Fingerprint: e.fingerprint,
			Payload:     append([]byte(nil), e.payload...),
			StoredAt:    e.at,
		}, nil
	}
}

// Commit implements Store.
func (m *Memory) Commit(_ context.Context, key string, payload []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	e, ok := m.entries[key]
	if !ok {
		return errors.New("idempotency: commit without a reservation")
	}
	e.inFlight = false
	e.payload = append([]byte(nil), payload...)
	e.at = m.now()
	return nil
}

// Abort implements Store.
func (m *Memory) Abort(_ context.Context, key string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if e, ok := m.entries[key]; ok && e.inFlight {
		delete(m.entries, key)
	}
}

// Size reports how many records are held.
func (m *Memory) Size() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.entries)
}

// expireLocked drops records past their TTL, and reservations that were never
// committed - a process that crashed mid-send must not block the key forever.
func (m *Memory) expireLocked(now time.Time) {
	const inFlightTTL = 5 * time.Minute
	for k, e := range m.entries {
		age := now.Sub(e.at)
		if age > m.ttl || (e.inFlight && age > inFlightTTL) {
			delete(m.entries, k)
		}
	}
}

// evictLocked makes room when the store is full, dropping the oldest record.
func (m *Memory) evictLocked() {
	if len(m.entries) < m.maxEntries {
		return
	}
	var oldestKey string
	var oldest time.Time
	for k, e := range m.entries {
		if oldestKey == "" || e.at.Before(oldest) {
			oldestKey, oldest = k, e.at
		}
	}
	delete(m.entries, oldestKey)
}

// Key builds the storage key for a client-supplied idempotency key.
//
// Namespacing by tenant and principal is what stops one caller from probing, or
// colliding with, another caller's keys: two tenants may legitimately choose
// the same UUID, and neither should ever see the other's receipt.
func Key(tenant, principal, operation, clientKey string) string {
	return strings.Join([]string{tenant, principal, operation, clientKey}, "\x00")
}

// Fingerprint hashes the arguments a key was used with, so a replay can verify
// the retry is really the same request.
func Fingerprint(v any) string {
	data, err := json.Marshal(v)
	if err != nil {
		// An unmarshalable argument cannot be fingerprinted; return a value
		// that will never match, so the call is treated as a mismatch rather
		// than silently replaying someone else's receipt.
		return "unfingerprintable"
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// ValidateKey checks a client-supplied key.
//
// The character set is deliberately narrow. The key becomes part of a storage
// key and appears in audit records; permitting arbitrary bytes there invites
// both log injection and key-namespace confusion.
func ValidateKey(key string) error {
	if len(key) > MaxKeyLength {
		return errors.New("idempotency key is too long")
	}
	if len(key) < MinKeyLength {
		return errors.New("idempotency key must be at least 8 characters")
	}
	for i := 0; i < len(key); i++ {
		c := key[i]
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '-' || c == '_' || c == '.' || c == ':'
		if !ok {
			return errors.New("idempotency key may contain only letters, digits, '-', '_', '.' and ':'")
		}
	}
	return nil
}
