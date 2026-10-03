package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Data classification for the fields this server handles.
//
// The classification is not decoration: it decides three separate things, and
// each is enforced somewhere different.
//
//	class          exposed to a client   written to logs/audit   masked on demand
//	IDENTIFIER     yes                   yes                     no
//	PII            yes, with a scope     never in the clear      yes
//	SENSITIVE      never                 never                   n/a
//	OPERATIONAL    yes                   yes                     no
//
// Field-by-field:
//
//	customer_id, order_id, tenant_id   IDENTIFIER
//	name, email                        PII
//	country                            PII (indirect; low sensitivity)
//	status, tier, version, timestamps  OPERATIONAL
//	notification subject, body         SENSITIVE - customer-facing content,
//	                                   never logged, never echoed back
//	bearer tokens, API tokens          SENSITIVE - never leave the process
//
// Errors carry no PII beyond the identifier the caller already supplied, which
// is why domain.NotFound quotes the id and nothing else.
const (
	ClassIdentifier  = "IDENTIFIER"
	ClassPII         = "PII"
	ClassSensitive   = "SENSITIVE"
	ClassOperational = "OPERATIONAL"
)

// MaskEmail renders an address for a log or audit record without disclosing it.
//
// The local part keeps its first character and the domain keeps its last label,
// which is enough to correlate two records about the same person while leaving
// the address itself unrecoverable: "ops@acme.example" -> "o***@***.example".
// A value that is not shaped like an address is masked whole, since it may be
// anything.
func MaskEmail(email string) string {
	e := strings.TrimSpace(email)
	if e == "" {
		return ""
	}
	at := strings.LastIndex(e, "@")
	if at <= 0 || at == len(e)-1 {
		return "***"
	}
	local, host := e[:at], e[at+1:]
	tld := host
	if dot := strings.LastIndex(host, "."); dot >= 0 && dot < len(host)-1 {
		tld = host[dot+1:]
	}
	return local[:1] + "***@***." + tld
}

// MaskName renders a display name for a log or audit record.
//
// Only the first character survives: a customer name is frequently a person's
// name, and an audit trail needs to distinguish records, not read them.
func MaskName(name string) string {
	n := strings.TrimSpace(name)
	if n == "" {
		return ""
	}
	return n[:1] + strings.Repeat("*", min(len(n)-1, 7))
}

// Fingerprint is a stable, non-reversible tag for a value.
//
// It exists for the case where an operator must answer "is this the same
// address as the one in yesterday's incident?" without either record ever
// holding the address. Truncated to 16 hex characters: long enough that a
// collision is not a practical concern for audit correlation, short enough to
// read.
func Fingerprint(v string) string {
	if v == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(v))))
	return hex.EncodeToString(sum[:])[:16]
}
