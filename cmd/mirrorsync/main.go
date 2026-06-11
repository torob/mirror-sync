package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"mirrorsync/internal/app"
	"mirrorsync/internal/config"
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
	a := app.New(cfg)
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
	default:
		fmt.Fprintln(os.Stderr, app.CommandUsage())
		return 2
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}
