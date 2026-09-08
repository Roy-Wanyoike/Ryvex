package state

// EncodeCursor returns the opaque pagination token for the list offset
// n. It is exported so durable Store backends (e.g. the Postgres
// store) produce byte-identical cursors to the in-memory reference.
func EncodeCursor(n int) string { return encodeCursor(n) }

// DecodeCursor parses a cursor produced by EncodeCursor. It returns
// ErrBadRequest for malformed tokens, mirroring ListResources.
func DecodeCursor(c string) (int, error) { return decodeCursor(c) }
