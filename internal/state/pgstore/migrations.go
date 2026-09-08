package pgstore

import _ "embed"

// Embedded schema migrations. Keeping the SQL in .sql files (compiled
// into the binary) means the schema ships with ryvexd and Migrate
// brings any database up to date on boot.
var (
	//go:embed migrations/0001_init.sql
	migration0001 string
)
