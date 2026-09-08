package state

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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
	audit   []AuditEntry
	seq     uint64
}

// NewStore returns an empty store.
func NewStore() *Store {
	return &Store{byID: map[string]*Resource{}, byLogic: map[string]string{}}
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
		offset = n
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
	end := offset + limit
	if offset > len(all) {
		offset = len(all)
	}
	if end > len(all) {
		end = len(all)
	}
	page := make([]*Resource, 0, end-offset)
	for _, r := range all[offset:end] {
		page = append(page, r.DeepCopy())
	}
	next := ""
	if end < len(all) {
		next = encodeCursor(end)
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

// Count returns the number of stored resources (used by tests and /healthz).
func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byID)
}

// AuditOptions filters the audit log.
type AuditOptions struct {
	Org   string
	Kind  string
	Limit int
}

// ListAudit returns audit entries newest-first.
func (s *Store) ListAudit(o AuditOptions) []AuditEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	limit := o.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	out := make([]AuditEntry, 0, limit)
	for i := len(s.audit) - 1; i >= 0 && len(out) < limit; i-- {
		e := s.audit[i]
		if o.Org != "" && !strings.HasPrefix(e.LogicalKey, o.Org+"/") {
			continue
		}
		if o.Kind != "" && e.Kind != o.Kind {
			continue
		}
		out = append(out, e)
	}
	return out
}

func (s *Store) appendAuditLocked(actor, action string, r *Resource) {
	s.seq++
	s.audit = append(s.audit, AuditEntry{
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

func encodeCursor(n int) string {
	return base64.RawURLEncoding.EncodeToString([]byte{byte(n >> 8), byte(n)})
}

func decodeCursor(c string) (int, error) {
	b, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil || len(b) != 2 {
		return 0, ErrBadRequest
	}
	return int(b[0])<<8 | int(b[1]), nil
}
