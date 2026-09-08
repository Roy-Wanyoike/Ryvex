package state

// EncodeCursor returns the opaque pagination token for the list offset
// n. It is exported so durable Store backends (e.g. the Postgres
// store) produce byte-identical cursors to the in-memory reference.
//
// The token is an 8-byte big-endian uint64 (v2, issue #39) so offsets
// beyond 65,535 no longer truncate. DecodeCursor still accepts the
// legacy 2-byte form for tokens issued before the upgrade.
func EncodeCursor(n uint64) string { return encodeCursor(n) }

// DecodeCursor parses a cursor produced by EncodeCursor. It returns
// ErrBadRequest for malformed tokens or offsets past maxCursorOffset,
// mirroring ListResources. Legacy 2-byte (v1) cursors decode with
// unchanged offset semantics.
func DecodeCursor(c string) (uint64, error) { return decodeCursor(c) }
