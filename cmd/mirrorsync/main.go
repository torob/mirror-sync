package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/torob/mirror-sync/internal/app"
	"github.com/torob/mirror-sync/internal/config"
	"github.com/torob/mirror-sync/internal/logging"
)

func main() {
	os.Exit(run())
}

func run() int {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, app.CommandUsage())
		return 2
	}
	cmd := os.Args[1]
	switch cmd {
	case "plan", "sync", "verify", "prune", "run":
	default:
		fmt.Fprintln(os.Stderr, app.CommandUsage())
		return 2
	}
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := fs.String("config", "", "configuration file")
	if err := fs.Parse(os.Args[2:]); err != nil {
		return 2
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	logger := logging.New(cfg.Logging, os.Stderr)
	started := time.Now()
	logger.Info("command started", "command", cmd)
	a := app.New(cfg, logger)
	switch cmd {
	case "plan":
		err = a.Plan(ctx)
	case "sync":
		err = a.Sync(ctx)
	case "verify":
		err = a.Verify(ctx)
	case "prune":
		err = a.Prune(ctx)
	case "run":
		err = a.Run(ctx)
	}
	if err != nil {
		if cfg.Logging.Level == "off" {
			fmt.Fprintln(os.Stderr, err)
		} else {
			logger.Error("command failed", "command", cmd, "duration", time.Since(started))
		}
		return 1
	}
	logger.Info("command completed", "command", cmd, "duration", time.Since(started))
	return 0
}
