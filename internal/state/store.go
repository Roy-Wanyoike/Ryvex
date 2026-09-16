package state

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math"
	"sort"
	"strings"
	"sync"
	"time"
)

// WriteOptions carries provenance for a mutation; every change is
// attributed to an actor and optionally a reason, both of which land
// in the audit log.
type WriteOptions struct {
	Actor  string
	Reason string
}

// Store is an in-memory, mutex-guarded resource store with
// compare-and-swap semantics and an append-only audit log. It is the
// reference implementation of the state contract; the API surface is
// designed so a durable backend can be swapped in later.
type Store struct {
	mu      sync.RWMutex
	byID    map[string]*Resource
	byLogic map[string]string // logical key -> id
	// Audit retention ring (issue #85): a fixed-capacity ring keeping
	// the newest auditCap entries with oldest-first eviction. The
	// backing array is pre-allocated once in NewStore and never grows
	// or reallocates; while len(audit) < auditCap entries append, and
	// once full auditWrite marks the next slot to overwrite (the
	// oldest entry). auditEvicted counts evictions; seq advances once
	// per entry and is never reset, staying monotonic across evictions
	// (mirroring the pgstore seq column that orders its audit table).
	audit        []AuditEntry
	auditWrite   int
	auditCap     int
	auditEvicted uint64
	seq          uint64
}

// DefaultAuditCap is the default audit-retention cap for the memory
// backend (issue #85): the ring keeps the newest 10,000 entries and
// evicts oldest-first once full. The Postgres backend needs no cap —
// its audit table is the durable compliance record and is meant to
// grow with traffic; only the in-memory log was unbounded.
const DefaultAuditCap = 10000

// NewStore returns an empty store. Options tune optional behaviour;
// the zero-option form keeps the historical defaults (audit cap =
// DefaultAuditCap, issue #85), so existing call sites are unchanged.
func NewStore(opts ...Option) *Store {
	c := storeConfig{auditCap: DefaultAuditCap}
	for _, opt := range opts {
		if opt != nil {
			opt(&c)
		}
	}
	if c.auditCap <= 0 {
		c.auditCap = DefaultAuditCap
	}
	return &Store{
		byID:     map[string]*Resource{},
		byLogic:  map[string]string{},
		audit:    make([]AuditEntry, 0, c.auditCap), // pre-allocated ring, never grown
		auditCap: c.auditCap,
	}
}

// Option adjusts optional Store behaviour at construction (issue #85).
type Option func(*storeConfig)

type storeConfig struct {
	auditCap int
}

// WithAuditCap bounds the in-memory audit log to the newest n entries,
// evicting oldest-first (issue #85). n <= 0 falls back to
// DefaultAuditCap. The Postgres backend ignores the knob: its audit
// table is unbounded by design.
func WithAuditCap(n int) Option {
	return func(c *storeConfig) {
		if n > 0 {
			c.auditCap = n
		}
	}
}

func newID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return "r-" + hex.EncodeToString(b[:])
}

func newAuditID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return "a-" + hex.EncodeToString(b[:])
}

// Create validates and stores a new resource. Spec, status phase and
// timestamps are normalised; the caller receives the stored copy.
func (s *Store) CreateResource(r *Resource, opts WriteOptions) (*Resource, error) {
	if r == nil {
		return nil, ErrValidation
	}
	if opts.Actor == "" {
		opts.Actor = "anonymous"
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	key := r.LogicalKey()
	if _, taken := s.byLogic[key]; taken {
		return nil, ErrAlreadyExists
	}
	now := time.Now().UTC()
	stored := r.DeepCopy()
	stored.ID = newID()
	stored.Generation = 1
	stored.CreatedAt = now
	stored.UpdatedAt = now
	if stored.Status.Phase == "" {
		stored.Status.Phase = PhasePending
	}
	stored.Status.ObservedGen = 0
	stored.Status.UpdatedAt = now

	s.byID[stored.ID] = stored
	s.byLogic[key] = stored.ID
	s.appendAuditLocked(opts.Actor, "created", stored)
	return stored.DeepCopy(), nil
}

// GetResource fetches by opaque ID.
func (s *Store) GetResource(id string) (*Resource, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.byID[id]
	if !ok {
		return nil, ErrNotFound
	}
	return r.DeepCopy(), nil
}

// GetByLogicalKey fetches by org/project/env/kind/name address.
func (s *Store) GetByLogicalKey(org, project, env, kind, name string) (*Resource, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.byLogic[logical(org, project, env, kind, name)]
	if !ok {
		return nil, ErrNotFound
	}
	return s.byID[id].DeepCopy(), nil
}

// ListOptions filters and paginates list queries. Cursor is the opaque
// token returned in a previous page.
type ListOptions struct {
	Org     string
	Project string
	Env     string
	Kind    string
	Limit   int
	Cursor  string
}

// ListResources returns a page of resources matching the filters,
// ordered by creation time then ID for stable pagination.
func (s *Store) ListResources(o ListOptions) ([]*Resource, string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	offset := 0
	if o.Cursor != "" {
		n, err := decodeCursor(o.Cursor)
		if err != nil {
			return nil, "", ErrBadRequest
		}
		// decodeCursor bounds n to maxCursorOffset, so the uint64
		// fits an int on every platform.
		offset = int(n)
	}

	all := make([]*Resource, 0, len(s.byID))
	for _, r := range s.byID {
		if o.Org != "" && r.Org != o.Org {
			continue
		}
		if o.Project != "" && r.Project != o.Project {
			continue
		}
		if o.Env != "" && r.Env != o.Env {
			continue
		}
		if o.Kind != "" && r.Kind != o.Kind {
			continue
		}
		all = append(all, r)
	}
	sort.Slice(all, func(i, j int) bool {
		if !all[i].CreatedAt.Equal(all[j].CreatedAt) {
			return all[i].CreatedAt.Before(all[j].CreatedAt)
		}
		return all[i].ID < all[j].ID
	})

	limit := o.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	// Clamp the offset BEFORE computing end: a hostile or stale
	// cursor near the int ceiling must not overflow offset+limit.
	if offset > len(all) {
		offset = len(all)
	}
	end := offset + limit
	if end > len(all) {
		end = len(all)
	}
	page := make([]*Resource, 0, end-offset)
	for _, r := range all[offset:end] {
		page = append(page, r.DeepCopy())
	}
	next := ""
	if end < len(all) {
		next = encodeCursor(uint64(end))
	}
	return page, next, nil
}

// UpdateResource applies fn to the resource under a CAS check: if the
// caller pins ExpectedGeneration and it no longer matches, ErrConflict
// is returned and nothing changes.
type UpdateOptions struct {
	WriteOptions
	ExpectedGeneration int64 // 0 = skip CAS
}

// UpdateResource mutates spec/labels via fn. Generation and UpdatedAt
// advance only when spec or labels actually change; status is not
// writable by users (the reconciler owns it).
func (s *Store) UpdateResource(id string, fn func(*Resource) error, o UpdateOptions) (*Resource, error) {
	if o.Actor == "" {
		o.Actor = "anonymous"
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	cur, ok := s.byID[id]
	if !ok {
		return nil, ErrNotFound
	}
	if o.ExpectedGeneration != 0 && o.ExpectedGeneration != cur.Generation {
		return nil, ErrConflict
	}
	work := cur.DeepCopy()
	if err := fn(work); err != nil {
		return nil, err
	}
	if err := work.Validate(); err != nil {
		return nil, err
	}
	if !specLabelsEqual(cur, work) {
		work.Generation = cur.Generation + 1
	}
	now := time.Now().UTC()
	work.UpdatedAt = now
	s.byID[id] = work
	if !specLabelsEqual(cur, work) {
		s.appendAuditLocked(o.Actor, "updated", work)
	}
	return work.DeepCopy(), nil
}

// UpdateStatus is the reconciler-only path for status transitions. It
// never bumps the spec generation but stamps the observed generation.
func (s *Store) UpdateStatus(id string, phase, message string, actor WriteOptions) error {
	if actor.Actor == "" {
		actor.Actor = "reconciler"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.byID[id]
	if !ok {
		return ErrNotFound
	}
	now := time.Now().UTC()
	if r.Status.Phase != phase || r.Status.Message != message {
		r.Status.Phase = phase
		r.Status.Message = message
		r.Status.UpdatedAt = now
		r.UpdatedAt = now
	}
	r.Status.ObservedGen = r.Generation
	s.appendAuditLocked(actor.Actor, "status_changed", r)
	return nil
}

// DeleteResource removes a resource by ID.
func (s *Store) DeleteResource(id string, opts WriteOptions) error {
	if opts.Actor == "" {
		opts.Actor = "anonymous"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.byID[id]
	if !ok {
		return ErrNotFound
	}
	delete(s.byID, id)
	delete(s.byLogic, r.LogicalKey())
	s.appendAuditLocked(opts.Actor, "deleted", r)
	return nil
}

// Ping reports store health for /healthz and /readyz (issue #71).
// The in-memory store has no external dependency, so it is always
// healthy; the method exists so both backends share the state.Backend
// contract.
func (s *Store) Ping(_ context.Context) error { return nil }

// Count returns the number of stored resources (used by tests and
// /healthz). The in-memory store cannot fail; the error return keeps
// parity with state.Backend (issue #71).
func (s *Store) Count() (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byID), nil
}

// CountByKindPhase returns how many resources exist per kind and
// lifecycle phase. It backs the ryvex_resources metrics gauge
// (issue #17): a read-only snapshot with no deep copies, refreshed by
// the reconciler on each scan.
func (s *Store) CountByKindPhase() (map[string]map[string]int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]map[string]int64, len(s.byID))
	for _, r := range s.byID {
		ph := out[r.Kind]
		if ph == nil {
			ph = make(map[string]int64, 4)
			out[r.Kind] = ph
		}
		ph[r.Status.Phase]++
	}
	return out, nil
}

// AuditOptions filters the audit log.
type AuditOptions struct {
	Org   string
	Kind  string
	Limit int
}

// ListAudit returns audit entries newest-first. The in-memory store
// cannot fail; the error return keeps parity with state.Backend
// (issue #71).
//
// Retention (issue #85): the memory backend keeps at most AuditCap
// entries (DefaultAuditCap by default; WithAuditCap / ryvexd
// --audit-cap override) and evicts oldest-first once full, so the
// newest-first contract is unaffected — evicted entries are simply
// absent from listings, never phantom or reordered. Offset cursors
// built from the shared v2 helpers (the 8-byte base64url tokens the
// list pagination issues) keep decoding for any offset that was ever
// minted: an offset that now lands past the retained window clamps to
// an empty page exactly like a cursor past the end of a list, so a
// walk across the eviction boundary can neither error nor loop. (The
// audit listing itself is limit-paged; ListResources owns the
// offset-cursor machinery this guarantee refers to.) The Postgres
// backend needs no cap: its audit table is the durable record.
func (s *Store) ListAudit(o AuditOptions) ([]AuditEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	limit := o.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	n := len(s.audit)
	out := make([]AuditEntry, 0, limit)
	for k := 0; k < n && len(out) < limit; k++ {
		// newest-first over the ring: (auditWrite-1-k) mod n. The +n
		// keeps the operand non-negative for every k < n.
		e := s.audit[(s.auditWrite-1-k+n)%n]
		if o.Org != "" && !strings.HasPrefix(e.LogicalKey, o.Org+"/") {
			continue
		}
		if o.Kind != "" && e.Kind != o.Kind {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

// AuditEvicted reports how many audit entries the memory backend has
// evicted oldest-first since construction (issue #85). A steadily
// climbing value is the operational signal that the retention ring is
// rolling; the Postgres backend never evicts its audit table.
func (s *Store) AuditEvicted() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.auditEvicted
}

func (s *Store) appendAuditLocked(actor, action string, r *Resource) {
	s.appendAuditRingLocked(AuditEntry{
		ID:         newAuditID(),
		Time:       time.Now().UTC(),
		Actor:      actor,
		Action:     action,
		ResourceID: r.ID,
		Kind:       r.Kind,
		LogicalKey: r.LogicalKey(),
		Generation: r.Generation,
	})
}

// appendAuditRingLocked writes one entry into the audit ring (issue
// #85). Below the cap it appends within the pre-reserved capacity —
// the backing array is allocated once in NewStore and never grows or
// reallocates — and at the cap it overwrites the oldest slot
// (oldest-first eviction), advancing auditWrite and the eviction
// counter. seq advances exactly once per entry and is never reset, so
// the audit sequence stays monotonic across evictions.
func (s *Store) appendAuditRingLocked(e AuditEntry) {
	s.seq++
	if s.auditCap <= 0 { // defensive: a zero-value Store stays bounded
		s.auditCap = DefaultAuditCap
	}
	if len(s.audit) < s.auditCap {
		s.audit = append(s.audit, e)
		return
	}
	s.audit[s.auditWrite] = e
	s.auditWrite++
	if s.auditWrite == s.auditCap {
		s.auditWrite = 0
	}
	s.auditEvicted++
}

// AppendAudit records a caller-built audit entry for outcomes that are
// not resource mutations — e.g. webhook delivery attempts reported by
// the webhook dispatcher. Missing ID and Time are filled in; the
// completed entry is returned. Filterable via ListAudit like any
// other entry (org filtering keys off LogicalKey). The in-memory
// store cannot fail; the error return keeps parity with state.Backend
// (issue #71).
func (s *Store) AppendAudit(e AuditEntry) (AuditEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e.ID == "" {
		e.ID = newAuditID()
	}
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	s.appendAuditRingLocked(e)
	return e, nil
}

func logical(org, project, env, kind, name string) string {
	return strings.Join([]string{org, project, env, kind, name}, "/")
}

func specLabelsEqual(a, b *Resource) bool {
	eq := func(m1, m2 map[string]string) bool {
		if len(m1) != len(m2) {
			return false
		}
		for k, v := range m1 {
			if m2[k] != v {
				return false
			}
		}
		return true
	}
	if !eq(a.Labels, b.Labels) {
		return false
	}
	r1, _ := json.Marshal(a.Spec)
	r2, _ := json.Marshal(b.Spec)
	return string(r1) == string(r2)
}

// Cursor format (issue #39):
//
//      v2 (current):  8 bytes, big-endian uint64 offset, base64url
//      v1 (legacy):   2 bytes, big-endian offset, base64url
//
// The v1 cursor wrapped at 65,535: larger offsets silently truncated
// and decodeCursor handed back a small WRONG offset, so pages
// duplicated. v2 encodes the full 64-bit offset; decode still accepts
// the legacy 2-byte form (same offset semantics) so tokens issued
// before the upgrade keep working.

// maxCursorOffset is the decode bound. No legitimate list page can
// produce an offset beyond it (that would need >2^31 rows), and
// keeping offsets within int32 range makes the uint64->int conversion
// and offset+limit arithmetic safe on every platform. Offsets past it
// are rejected with ErrBadRequest instead of wrapping silently.
const maxCursorOffset = math.MaxInt32

func encodeCursor(n uint64) string {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], n)
	return base64.RawURLEncoding.EncodeToString(b[:])
}

func decodeCursor(c string) (uint64, error) {
	b, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil {
		return 0, ErrBadRequest
	}
	switch len(b) {
	case 8: // v2
		n := binary.BigEndian.Uint64(b)
		if n > maxCursorOffset {
			return 0, ErrBadRequest
		}
		return n, nil
	case 2: // v1 legacy: offset semantics unchanged
		return uint64(b[0])<<8 | uint64(b[1]), nil
	default:
		return 0, ErrBadRequest
	}
}
