package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
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
	Logger               *slog.Logger
	repoRunnersOverride  func() []repoTask
	repositoryRetryDelay func(int) time.Duration
	cycleSequence        atomic.Uint64
}

var discardLogger = slog.New(slog.NewTextHandler(io.Discard, nil))

func New(cfg *config.Config, logger *slog.Logger) *App {
	if logger == nil {
		logger = discardLogger
	}
	return &App{
		Config: cfg,
		HTTP:   httpx.NewFactory(cfg.Retries(), limit.New(cfg.MaxInFlightRequests()), logger),
		Logger: logger,
	}
}

func (a *App) Plan(ctx context.Context) error {
	started := time.Now()
	a.logger().Info("plan started")
	plans, err := a.collectPlans(ctx)
	if err != nil {
		a.logger().Error("plan failed", "duration", time.Since(started), "error", err)
		return err
	}
	for _, p := range plans {
		fmt.Printf("%s/%s publish=%s metadata=%d packages=%d bytes=%d\n", p.Kind, p.Name, p.PublishPath, p.MetadataFiles, p.Packages, p.Bytes)
		for _, src := range p.Sources {
			fmt.Printf("  source %s\n", src)
		}
	}
	a.logger().Info("plan completed", "repositories", len(plans), "duration", time.Since(started))
	return nil
}

func (a *App) Sync(ctx context.Context) error {
	return a.syncCycle(ctx, "oneshot")
}

func (a *App) syncCycle(ctx context.Context, trigger string) error {
	cycle := a.cycleSequence.Add(1)
	return a.runRepositories(ctx, "sync", trigger, cycle, a.Config.Sync.RepositoryRetries, func(ctx context.Context, runner repoRunner) (model.OperationStats, error) {
		return runner.Sync(ctx)
	})
}

func (a *App) Verify(ctx context.Context) error {
	return a.runRepositories(ctx, "verify", "oneshot", 0, 0, func(ctx context.Context, runner repoRunner) (model.OperationStats, error) {
		return runner.Verify(ctx)
	})
}

func (a *App) Prune(ctx context.Context) error {
	return a.runRepositories(ctx, "prune", "oneshot", 0, 0, func(ctx context.Context, runner repoRunner) (model.OperationStats, error) {
		removed, err := runner.Prune(ctx)
		for _, rel := range removed {
			fmt.Printf("pruned %s\n", rel)
		}
		return model.OperationStats{FilesPruned: len(removed)}, err
	})
}

func (a *App) Run(ctx context.Context) error {
	if a.Config.Sync.Schedule.Interval == "" && a.Config.Sync.Schedule.Cron == "" {
		err := fmt.Errorf("run requires sync.schedule.interval or sync.schedule.cron")
		a.logger().Error("scheduler failed", "error", err)
		return err
	}
	a.logger().Info("scheduler started")
	_ = a.syncCycle(ctx, "startup")
	next, err := scheduler.New(a.Config.Sync.Schedule)
	if err != nil {
		a.logger().Error("scheduler failed", "error", err)
		return err
	}
	for {
		nextRun := next.Next(time.Now())
		wait := time.Until(nextRun)
		if wait < 0 {
			wait = 0
		}
		a.logger().Info("scheduler waiting", "next_run", nextRun.UTC(), "wait", wait)
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			a.logger().Info("scheduler stopped", "reason", ctx.Err())
			return nil
		case <-timer.C:
		}
		_ = a.syncCycle(ctx, "scheduled")
	}
}

type repoRunner interface {
	Sync(context.Context) (model.OperationStats, error)
	Verify(context.Context) (model.OperationStats, error)
	Prune(context.Context) ([]string, error)
}

type planRunner interface {
	Plan(context.Context) (model.RepositoryPlan, error)
}

type repoTask struct {
	label  string
	runner repoRunner
}

type repositoryResults struct {
	stats     model.OperationStats
	succeeded int
	failed    int
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

func (a *App) runRepositories(ctx context.Context, operation, trigger string, cycle uint64, retries int, fn func(context.Context, repoRunner) (model.OperationStats, error)) error {
	started := time.Now()
	runners := a.repoRunners()
	fields := []any{"operation", operation, "trigger", trigger, "repositories", len(runners)}
	if cycle > 0 {
		fields = append(fields, "cycle", cycle)
	}
	a.logger().Info("operation started", fields...)
	results, err := a.eachRepo(ctx, operation, cycle, runners, retries, fn)
	fields = append(fields,
		"repositories_succeeded", results.succeeded,
		"repositories_failed", results.failed,
		"duration", time.Since(started),
	)
	fields = append(fields, statsFields(results.stats)...)
	if err != nil {
		a.logger().Error("operation failed", fields...)
	} else {
		a.logger().Info("operation completed", fields...)
	}
	return err
}

func (a *App) eachRepo(ctx context.Context, operation string, cycle uint64, runners []repoTask, retries int, fn func(context.Context, repoRunner) (model.OperationStats, error)) (repositoryResults, error) {
	errs := make([]error, len(runners))
	stats := make([]model.OperationStats, len(runners))
	var wg sync.WaitGroup
	for i, task := range runners {
		i, task := i, task
		wg.Add(1)
		go func() {
			defer wg.Done()
			stats[i], errs[i] = a.runRepoWithRetries(ctx, operation, cycle, task, retries, fn)
		}()
	}
	wg.Wait()
	var results repositoryResults
	for i, err := range errs {
		results.stats.Add(stats[i])
		if err == nil {
			results.succeeded++
		} else {
			results.failed++
		}
	}
	return results, errors.Join(errs...)
}

func (a *App) runRepoWithRetries(ctx context.Context, operation string, cycle uint64, task repoTask, retries int, fn func(context.Context, repoRunner) (model.OperationStats, error)) (model.OperationStats, error) {
	var total model.OperationStats
	label := task.label
	if label == "" {
		label = "repository"
	}
	for attempt := 0; attempt <= retries; attempt++ {
		if err := ctx.Err(); err != nil {
			fields := append(repositoryFields(operation, label, cycle), "attempt", attempt+1, "error", err)
			a.logger().Error("repository failed", fields...)
			return total, fmt.Errorf("%s: %w", label, err)
		}
		attemptStarted := time.Now()
		baseFields := repositoryFields(operation, label, cycle)
		a.logger().Info("repository attempt started", append(baseFields, "attempt", attempt+1, "max_attempts", retries+1)...)
		stats, err := fn(ctx, task.runner)
		total.Add(stats)
		if err == nil {
			fields := append(baseFields, "attempt", attempt+1, "duration", time.Since(attemptStarted))
			fields = append(fields, statsFields(stats)...)
			a.logger().Info("repository attempt completed", fields...)
			return total, nil
		}
		if ctx.Err() != nil || attempt == retries {
			fields := append(baseFields, "attempt", attempt+1, "duration", time.Since(attemptStarted), "error", err)
			fields = append(fields, statsFields(stats)...)
			a.logger().Error("repository failed", fields...)
			return total, fmt.Errorf("%s: %w", label, err)
		}
		delay := a.repoRetryDelay(attempt + 1)
		retryFields := append(baseFields, "attempt", attempt+1, "next_attempt", attempt+2, "delay", delay, "error", err)
		a.logger().Warn("repository attempt failed; retrying", retryFields...)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			joined := errors.Join(err, ctx.Err())
			fields := append(repositoryFields(operation, label, cycle), "attempt", attempt+1, "error", joined)
			a.logger().Error("repository failed", fields...)
			return total, fmt.Errorf("%s: %w", label, joined)
		case <-timer.C:
		}
	}
	return total, nil
}

func repositoryFields(operation, repository string, cycle uint64) []any {
	fields := []any{"operation", operation, "repository", repository}
	if cycle > 0 {
		fields = append(fields, "cycle", cycle)
	}
	return fields
}

func (a *App) logger() *slog.Logger {
	if a.Logger == nil {
		return discardLogger
	}
	return a.Logger
}

func statsFields(stats model.OperationStats) []any {
	return []any{
		"files_checked", stats.FilesChecked,
		"files_reused", stats.FilesReused,
		"files_downloaded", stats.FilesDownloaded,
		"files_repaired", stats.FilesRepaired,
		"bytes_downloaded", stats.BytesDownloaded,
		"files_pruned", stats.FilesPruned,
	}
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
