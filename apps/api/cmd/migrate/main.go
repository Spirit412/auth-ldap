// cmd/migrate applies or rolls back the embedded SQL migrations manually
// (useful for ops; the API binary also migrates automatically at startup
// when DB_MIGRATE=true).
package main

import (
	"fmt"
	"os"

	"aps.local/apps/api/internal/config"
	"aps.local/apps/api/internal/userstore"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		fatal("config: %v", err)
	}
	dir := "up"
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}
	switch dir {
	case "up":
		if err := userstore.MigrateUp(cfg.MigrateDSN()); err != nil {
			fatal("migrate up: %v", err)
		}
		fmt.Println("migrations applied")
	case "down":
		if err := userstore.MigrateDown(cfg.MigrateDSN()); err != nil {
			fatal("migrate down: %v", err)
		}
		fmt.Println("migrations rolled back")
	default:
		fatal("usage: migrate [up|down]", nil)
	}
}

func fatal(format string, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, format+"\n", err)
	} else {
		fmt.Fprintln(os.Stderr, format)
	}
	os.Exit(1)
}
