package state_test

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"math"
	"testing"

	"github.com/Roy-Wanyoike/Ryvex/internal/state"
)

// legacyCursor builds a v1 (pre-#39) pagination token: a 2-byte
// big-endian offset. The store must keep decoding these forever —
// tokens issued before the 64-bit upgrade are still held by clients.
func legacyCursor(n int) string {
	return base64.RawURLEncoding.EncodeToString([]byte{byte(n >> 8), byte(n)})
}

func overboundCursor(n uint64) string {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], n)
	return base64.RawURLEncoding.EncodeToString(b[:])
}

// TestCursorRoundTrip pins the v2 cursor: 8 bytes (11 base64url
// chars, no padding) encoding the full 64-bit offset. The table
// straddles the old 65,535 wrap point — 65,536 and beyond must no
// longer truncate to a small wrong offset.
func TestCursorRoundTrip(t *testing.T) {
	for _, n := range []uint64{0, 1, 100, 65535, 65536, 1000000, uint64(math.MaxInt32)} {
		tok := state.EncodeCursor(n)
		if len(tok) != 11 {
			t.Errorf("offset %d: cursor %q must be 11 chars (8 bytes), got %d", n, tok, len(tok))
		}
		got, err := state.DecodeCursor(tok)
		if err != nil {
			t.Errorf("offset %d: decode %q: %v", n, tok, err)
			continue
		}
		if got != n {
			t.Errorf("offset %d: round-trip got %d (silent truncation)", n, got)
		}
	}
}

// TestLegacyCursorStillDecodes: v1 2-byte cursors decode with the
// same offset semantics they always had.
func TestLegacyCursorStillDecodes(t *testing.T) {
	for _, n := range []int{0, 1, 50, 65535} {
		got, err := state.DecodeCursor(legacyCursor(n))
		if err != nil {
			t.Errorf("legacy offset %d: decode: %v", n, err)
			continue
		}
		if got != uint64(n) {
			t.Errorf("legacy offset %d: decoded %d", n, got)
		}
	}
}

// TestCursorRejectsBadTokens: malformed payloads and offsets past the
// decode bound must fail with ErrBadRequest, never a silently wrapped
// offset.
func TestCursorRejectsBadTokens(t *testing.T) {
	bad := map[string]string{
		"not base64":      "!!not-base64!!",
		"wrong width":     base64.RawURLEncoding.EncodeToString([]byte{1, 2, 3}),
		"past max int32":  overboundCursor(uint64(math.MaxInt32) + 1),
		"max uint64":      overboundCursor(math.MaxUint64),
		"empty-ish width": base64.RawURLEncoding.EncodeToString([]byte{1}),
	}
	for name, tok := range bad {
		got, err := state.DecodeCursor(tok)
		if !errors.Is(err, state.ErrBadRequest) {
			t.Errorf("%s (%q): want ErrBadRequest, got offset %d err %v", name, tok, got, err)
		}
	}
}

// TestListResourcesAcceptsLegacyCursor: pagination driven by a v1
// token must keep working end-to-end against the reference store.
func TestListResourcesAcceptsLegacyCursor(t *testing.T) {
	st := state.NewStore()
	for _, n := range []string{"a", "b", "c"} {
		if _, err := st.CreateResource(&state.Resource{
			Kind: "Node", Org: "acme", Project: "core", Env: "prod", Name: n,
			Spec: map[string]any{"replicas": 1},
		}, state.WriteOptions{Actor: "t"}); err != nil {
			t.Fatalf("seed %s: %v", n, err)
		}
	}
	all, _, err := st.ListResources(state.ListOptions{Limit: 10})
	if err != nil || len(all) != 3 {
		t.Fatalf("baseline list: %d items err %v", len(all), err)
	}

	// legacy cursor for offset 1 skips exactly the first item
	page, next, err := st.ListResources(state.ListOptions{Limit: 1, Cursor: legacyCursor(1)})
	if err != nil || len(page) != 1 || next == "" {
		t.Fatalf("legacy page: %d items next=%q err %v", len(page), next, err)
	}
	if page[0].ID != all[1].ID {
		t.Fatalf("legacy cursor skipped the wrong item: got %s want %s", page[0].ID, all[1].ID)
	}
	// the v2 cursor handed back must continue from the same point
	page2, next2, err := st.ListResources(state.ListOptions{Limit: 1, Cursor: next})
	if err != nil || len(page2) != 1 || next2 != "" {
		t.Fatalf("v2 continuation: %d items next=%q err %v", len(page2), next2, err)
	}
	if page2[0].ID != all[2].ID {
		t.Fatalf("v2 continuation skipped the wrong item: got %s want %s", page2[0].ID, all[2].ID)
	}
	// and a malformed token is still a 400, not an empty page
	if _, _, err := st.ListResources(state.ListOptions{Cursor: "@@bad@@"}); !errors.Is(err, state.ErrBadRequest) {
		t.Fatalf("bad cursor: want ErrBadRequest, got %v", err)
	}
}
