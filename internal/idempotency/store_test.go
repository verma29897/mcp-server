package idempotency

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestFirstUseReservesAndCommits(t *testing.T) {
	ctx := context.Background()
	s := NewMemory(time.Hour, 100)

	record, err := s.Begin(ctx, "k1", "fp1")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if record != nil {
		t.Fatal("a first use returned a replayable record")
	}
	if err := s.Commit(ctx, "k1", []byte(`{"message_id":"msg-1"}`)); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	replay, err := s.Begin(ctx, "k1", "fp1")
	if err != nil {
		t.Fatalf("second Begin: %v", err)
	}
	if replay == nil {
		t.Fatal("a repeat of the same request did not replay")
	}
	if string(replay.Payload) != `{"message_id":"msg-1"}` {
		t.Errorf("payload = %s, want the stored receipt", replay.Payload)
	}
}

func TestSameKeyWithDifferentArgumentsConflicts(t *testing.T) {
	ctx := context.Background()
	s := NewMemory(time.Hour, 100)

	if _, err := s.Begin(ctx, "k1", "fp-original"); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if err := s.Commit(ctx, "k1", []byte(`{}`)); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	// Replaying the first receipt here would tell the caller its second,
	// different message was sent when it never was.
	if _, err := s.Begin(ctx, "k1", "fp-different"); !errors.Is(err, ErrMismatch) {
		t.Fatalf("err = %v, want ErrMismatch", err)
	}
}

func TestConcurrentDuplicateIsRefusedNotQueued(t *testing.T) {
	ctx := context.Background()
	s := NewMemory(time.Hour, 100)

	if _, err := s.Begin(ctx, "k1", "fp1"); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if _, err := s.Begin(ctx, "k1", "fp1"); !errors.Is(err, ErrInFlight) {
		t.Fatalf("err = %v, want ErrInFlight while the first call is still running", err)
	}
}

func TestAbortReleasesTheKeyForARetry(t *testing.T) {
	ctx := context.Background()
	s := NewMemory(time.Hour, 100)

	if _, err := s.Begin(ctx, "k1", "fp1"); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	// The send failed. Holding the key would mean the caller can never retry
	// with the same key, which is the one thing the key exists to allow.
	s.Abort(ctx, "k1")

	record, err := s.Begin(ctx, "k1", "fp1")
	if err != nil {
		t.Fatalf("Begin after Abort: %v", err)
	}
	if record != nil {
		t.Fatal("a retry after a failed attempt replayed a receipt that was never stored")
	}
}

func TestAbortDoesNotDiscardACommittedRecord(t *testing.T) {
	ctx := context.Background()
	s := NewMemory(time.Hour, 100)

	_, _ = s.Begin(ctx, "k1", "fp1")
	_ = s.Commit(ctx, "k1", []byte(`{"message_id":"msg-1"}`))
	s.Abort(ctx, "k1")

	record, err := s.Begin(ctx, "k1", "fp1")
	if err != nil || record == nil {
		t.Fatalf("a committed record was dropped by a late Abort: record=%v err=%v", record, err)
	}
}

func TestRecordsExpire(t *testing.T) {
	ctx := context.Background()
	s := NewMemory(time.Hour, 100)
	now := time.Now()
	s.now = func() time.Time { return now }

	_, _ = s.Begin(ctx, "k1", "fp1")
	_ = s.Commit(ctx, "k1", []byte(`{}`))

	now = now.Add(2 * time.Hour)
	record, err := s.Begin(ctx, "k1", "fp1")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if record != nil {
		t.Fatal("a record past its TTL was still replayed")
	}
}

func TestStaleReservationDoesNotBlockTheKeyForever(t *testing.T) {
	ctx := context.Background()
	s := NewMemory(time.Hour, 100)
	now := time.Now()
	s.now = func() time.Time { return now }

	// A process that crashed between Begin and Commit leaves a reservation
	// nobody will ever release.
	_, _ = s.Begin(ctx, "k1", "fp1")

	now = now.Add(10 * time.Minute)
	if _, err := s.Begin(ctx, "k1", "fp1"); err != nil {
		t.Fatalf("a stale reservation blocked the key permanently: %v", err)
	}
}

func TestStoreIsBounded(t *testing.T) {
	ctx := context.Background()
	s := NewMemory(time.Hour, 10)

	for i := 0; i < 100; i++ {
		key := "k" + string(rune('a'+i%26)) + string(rune('a'+i/26))
		_, _ = s.Begin(ctx, key, "fp")
		_ = s.Commit(ctx, key, []byte(`{}`))
	}
	if got := s.Size(); got > 10 {
		t.Errorf("store holds %d records, want at most 10", got)
	}
}

func TestKeysAreNamespacedByTenantAndPrincipal(t *testing.T) {
	// Two tenants choosing the same UUID must not collide, and neither must
	// ever be able to read back the other's receipt.
	a := Key("tenant-a", "user-1", "send", "shared-uuid")
	b := Key("tenant-b", "user-1", "send", "shared-uuid")
	c := Key("tenant-a", "user-2", "send", "shared-uuid")
	if a == b || a == c || b == c {
		t.Fatalf("namespacing failed: %q %q %q", a, b, c)
	}
}

func TestFingerprintDistinguishesRequests(t *testing.T) {
	type msg struct {
		Body string `json:"b"`
	}
	hello, helloWorld := msg{"hello"}, msg{"hello world"}
	if Fingerprint(hello) == Fingerprint(helloWorld) {
		t.Error("two different messages share a fingerprint")
	}
	// Determinism: a retry fingerprints to the same value as the original, or
	// every retry would look like a mismatch and never replay.
	again := msg{"hello"}
	if Fingerprint(hello) != Fingerprint(again) {
		t.Error("the same message produced two fingerprints")
	}
}

func TestValidateKey(t *testing.T) {
	tests := []struct {
		name string
		key  string
		ok   bool
	}{
		{"uuid", "3f2b8c1a-9d4e-4b7a-8c2f-1e5d7a9b3c4d", true},
		{"hash", "a1b2c3d4e5f60718", true},
		{"too short", "abc", false},
		{"too long", strings.Repeat("a", MaxKeyLength+1), false},
		{"newline", "abcdefgh\nmore", false},
		{"path separator", "abcdefgh/../other", false},
		{"null byte", "abcdefgh\x00", false},
		{"space", "abcdefgh ijkl", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateKey(tc.key)
			if tc.ok && err != nil {
				t.Errorf("ValidateKey(%q) = %v, want nil", tc.key, err)
			}
			if !tc.ok && err == nil {
				t.Errorf("ValidateKey(%q) accepted an unsafe key", tc.key)
			}
		})
	}
}

func TestConcurrentBeginElectsOneWinner(t *testing.T) {
	ctx := context.Background()
	s := NewMemory(time.Hour, 100)

	const callers = 32
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		winners int
	)
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			record, err := s.Begin(ctx, "k1", "fp1")
			if err == nil && record == nil {
				mu.Lock()
				winners++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	// Exactly one caller may proceed to send. Anything else means a race in
	// the store becomes a duplicate message to a customer.
	if winners != 1 {
		t.Fatalf("%d callers were allowed to send, want exactly 1", winners)
	}
}
