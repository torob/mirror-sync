package app

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	"mirrorsync/internal/apk"
	"mirrorsync/internal/apt"
	"mirrorsync/internal/config"
	"mirrorsync/internal/httpx"
	"mirrorsync/internal/model"
	"mirrorsync/internal/scheduler"
)

type App struct {
	Config *config.Config
	HTTP   *httpx.Factory
}

func New(cfg *config.Config) *App {
	return &App{Config: cfg, HTTP: httpx.NewFactory(cfg.Retries())}
}

func (a *App) Plan(ctx context.Context) error {
	plans, err := a.collectPlans(ctx)
	if err != nil {
		return err
	}
	for _, p := range plans {
		fmt.Printf("%s/%s publish=%s metadata=%d packages=%d bytes=%d\n", p.Kind, p.Name, p.PublishPath, p.MetadataFiles, p.Packages, p.Bytes)
		for _, src := range p.Sources {
			fmt.Printf("  source %s\n", src)
		}
	}
	return nil
}

func (a *App) Sync(ctx context.Context) error {
	return a.eachRepo(ctx, func(ctx context.Context, runner repoRunner) error {
		return runner.Sync(ctx)
	})
}

func (a *App) Verify(ctx context.Context) error {
	return a.eachRepo(ctx, func(ctx context.Context, runner repoRunner) error {
		return runner.Verify(ctx)
	})
}

func (a *App) Prune(ctx context.Context) error {
	return a.eachRepo(ctx, func(ctx context.Context, runner repoRunner) error {
		removed, err := runner.Prune(ctx)
		for _, rel := range removed {
			fmt.Printf("pruned %s\n", rel)
		}
		return err
	})
}

func (a *App) Run(ctx context.Context) error {
	if a.Config.Sync.Schedule.Interval == "" && a.Config.Sync.Schedule.Cron == "" {
		return fmt.Errorf("run requires sync.schedule.interval or sync.schedule.cron")
	}
	fmt.Fprintln(os.Stderr, "starting immediate sync")
	if err := a.Sync(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "startup sync failed: %v\n", err)
	}
	next, err := scheduler.New(a.Config.Sync.Schedule)
	if err != nil {
		return err
	}
	for {
		wait := time.Until(next.Next(time.Now()))
		if wait < 0 {
			wait = 0
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
		if err := a.Sync(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "scheduled sync failed: %v\n", err)
		}
	}
}

type repoRunner interface {
	Sync(context.Context) error
	Verify(context.Context) error
	Prune(context.Context) ([]string, error)
}

type planRunner interface {
	Plan(context.Context) (model.RepositoryPlan, error)
}

func (a *App) collectPlans(ctx context.Context) ([]model.RepositoryPlan, error) {
	var plans []model.RepositoryPlan
	for _, runner := range a.planRunners() {
		p, err := runner.Plan(ctx)
		if err != nil {
			return nil, err
		}
		plans = append(plans, p)
	}
	return plans, nil
}

func (a *App) eachRepo(ctx context.Context, fn func(context.Context, repoRunner) error) error {
	runners := a.repoRunners()
	sem := make(chan struct{}, a.Config.Concurrency())
	g, ctx := errgroup.WithContext(ctx)
	for _, runner := range runners {
		runner := runner
		g.Go(func() error {
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return ctx.Err()
			}
			return fn(ctx, runner)
		})
	}
	return g.Wait()
}

func (a *App) repoRunners() []repoRunner {
	var out []repoRunner
	for _, repo := range a.Config.APT.Repositories {
		out = append(out, &apt.Runner{Config: a.Config, Repo: repo, HTTP: a.HTTP})
	}
	for _, repo := range a.Config.APK.Repositories {
		out = append(out, &apk.Runner{Config: a.Config, Repo: repo, HTTP: a.HTTP})
	}
	return out
}

func (a *App) planRunners() []planRunner {
	var out []planRunner
	for _, repo := range a.Config.APT.Repositories {
		out = append(out, &apt.Runner{Config: a.Config, Repo: repo, HTTP: a.HTTP})
	}
	for _, repo := range a.Config.APK.Repositories {
		out = append(out, &apk.Runner{Config: a.Config, Repo: repo, HTTP: a.HTTP})
	}
	return out
}

func CommandUsage() string {
	return strings.TrimSpace(`usage:
  mirrorsync plan   -config config.yaml
  mirrorsync sync   -config config.yaml
  mirrorsync verify -config config.yaml
  mirrorsync prune  -config config.yaml
  mirrorsync run    -config config.yaml`)
}
