// Package migrations embeds SQL migration files so they ship inside the
// binary (single-container deploy, no external migration assets).
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS
