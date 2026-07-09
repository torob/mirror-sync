package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/torob/mirror-sync/internal/apk"
	"github.com/torob/mirror-sync/internal/apt"
	"github.com/torob/mirror-sync/internal/config"
	"github.com/torob/mirror-sync/internal/httpx"
	"github.com/torob/mirror-sync/internal/limit"
	"github.com/torob/mirror-sync/internal/model"
	"github.com/torob/mirror-sync/internal/scheduler"
)

type App struct {
	Config               *config.Config
	HTTP                 *httpx.Factory
	repoRunnersOverride  func() []repoTask
	repositoryRetryDelay func(int) time.Duration
}

func New(cfg *config.Config) *App {
	return &App{Config: cfg, HTTP: httpx.NewFactory(cfg.Retries(), limit.New(cfg.MaxInFlightRequests()))}
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
	return a.eachRepo(ctx, a.Config.Sync.RepositoryRetries, func(ctx context.Context, runner repoRunner) error {
		return runner.Sync(ctx)
	})
}

func (a *App) Verify(ctx context.Context) error {
	return a.eachRepo(ctx, 0, func(ctx context.Context, runner repoRunner) error {
		return runner.Verify(ctx)
	})
}

func (a *App) Prune(ctx context.Context) error {
	return a.eachRepo(ctx, 0, func(ctx context.Context, runner repoRunner) error {
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

type repoTask struct {
	label  string
	runner repoRunner
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

func (a *App) eachRepo(ctx context.Context, retries int, fn func(context.Context, repoRunner) error) error {
	runners := a.repoRunners()
	errs := make([]error, len(runners))
	var wg sync.WaitGroup
	for i, task := range runners {
		i, task := i, task
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = a.runRepoWithRetries(ctx, task, retries, fn)
		}()
	}
	wg.Wait()
	return errors.Join(errs...)
}

func (a *App) runRepoWithRetries(ctx context.Context, task repoTask, retries int, fn func(context.Context, repoRunner) error) error {
	label := task.label
	if label == "" {
		label = "repository"
	}
	for attempt := 0; attempt <= retries; attempt++ {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
		err := fn(ctx, task.runner)
		if err == nil {
			return nil
		}
		if ctx.Err() != nil || attempt == retries {
			return fmt.Errorf("%s: %w", label, err)
		}
		timer := time.NewTimer(a.repoRetryDelay(attempt + 1))
		select {
		case <-ctx.Done():
			timer.Stop()
			return fmt.Errorf("%s: %w", label, errors.Join(err, ctx.Err()))
		case <-timer.C:
		}
	}
	return nil
}

func (a *App) repoRetryDelay(retry int) time.Duration {
	if a.repositoryRetryDelay != nil {
		return a.repositoryRetryDelay(retry)
	}
	return time.Duration(retry) * time.Second
}

func (a *App) repoRunners() []repoTask {
	if a.repoRunnersOverride != nil {
		return a.repoRunnersOverride()
	}
	var out []repoTask
	for _, repo := range a.Config.APT.Repositories {
		out = append(out, repoTask{
			label:  "apt/" + repo.Name,
			runner: &apt.Runner{Config: a.Config, Repo: repo, HTTP: a.HTTP},
		})
	}
	for _, repo := range a.Config.APK.Repositories {
		out = append(out, repoTask{
			label:  "apk/" + repo.Name,
			runner: &apk.Runner{Config: a.Config, Repo: repo, HTTP: a.HTTP},
		})
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
