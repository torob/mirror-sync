package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/torob/mirror-sync/internal/config"
)

type fakeRunner struct {
	syncFn   func(context.Context) error
	verifyFn func(context.Context) error
	pruneFn  func(context.Context) ([]string, error)
}

func (r *fakeRunner) Sync(ctx context.Context) error {
	if r.syncFn != nil {
		return r.syncFn(ctx)
	}
	return nil
}

func (r *fakeRunner) Verify(ctx context.Context) error {
	if r.verifyFn != nil {
		return r.verifyFn(ctx)
	}
	return nil
}

func (r *fakeRunner) Prune(ctx context.Context) ([]string, error) {
	if r.pruneFn != nil {
		return r.pruneFn(ctx)
	}
	return nil, nil
}

func TestEachRepoFailureDoesNotCancelOtherRepositories(t *testing.T) {
	var slowSawCanceled atomic.Bool
	slowDone := make(chan struct{})
	a := &App{
		Config: &config.Config{},
		repoRunnersOverride: func() []repoTask {
			return []repoTask{
				{
					label: "apt/ubuntu",
					runner: &fakeRunner{syncFn: func(context.Context) error {
						return errors.New("failed immediately")
					}},
				},
				{
					label: "apk/alpine",
					runner: &fakeRunner{syncFn: func(ctx context.Context) error {
						defer close(slowDone)
						time.Sleep(25 * time.Millisecond)
						if ctx.Err() != nil {
							slowSawCanceled.Store(true)
						}
						return nil
					}},
				},
			}
		},
	}

	err := a.Sync(context.Background())
	if err == nil {
		t.Fatal("Sync succeeded, want failed repository error")
	}
	<-slowDone
	if slowSawCanceled.Load() {
		t.Fatal("successful repository saw context cancellation from another repository failure")
	}
	if !strings.Contains(err.Error(), "apt/ubuntu") || !strings.Contains(err.Error(), "failed immediately") {
		t.Fatalf("Sync error = %v, want labeled failed repository", err)
	}
}

func TestEachRepoReportsAllRepositoryFailures(t *testing.T) {
	a := &App{
		Config: &config.Config{},
		repoRunnersOverride: func() []repoTask {
			return []repoTask{
				{label: "apt/ubuntu", runner: &fakeRunner{syncFn: func(context.Context) error { return errors.New("apt failed") }}},
				{label: "apk/alpine", runner: &fakeRunner{syncFn: func(context.Context) error { return errors.New("apk failed") }}},
			}
		},
	}

	err := a.Sync(context.Background())
	if err == nil {
		t.Fatal("Sync succeeded, want joined error")
	}
	for _, want := range []string{"apt/ubuntu", "apt failed", "apk/alpine", "apk failed"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("Sync error = %v, want %q", err, want)
		}
	}
}

func TestSyncRetriesFailedRepositoryAttempt(t *testing.T) {
	var calls atomic.Int32
	a := &App{
		Config: &config.Config{Sync: config.Sync{RepositoryRetries: 1}},
		repoRunnersOverride: func() []repoTask {
			return []repoTask{{
				label: "apt/ubuntu",
				runner: &fakeRunner{syncFn: func(context.Context) error {
					if calls.Add(1) == 1 {
						return errors.New("first attempt failed")
					}
					return nil
				}},
			}}
		},
		repositoryRetryDelay: func(int) time.Duration { return 0 },
	}

	if err := a.Sync(context.Background()); err != nil {
		t.Fatalf("Sync failed: %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("Sync calls = %d, want 2", got)
	}
}

func TestSyncDoesNotRetryAfterParentCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls atomic.Int32
	a := &App{
		Config: &config.Config{Sync: config.Sync{RepositoryRetries: 2}},
		repoRunnersOverride: func() []repoTask {
			return []repoTask{{
				label: "apt/ubuntu",
				runner: &fakeRunner{syncFn: func(context.Context) error {
					calls.Add(1)
					cancel()
					return errors.New("attempt failed")
				}},
			}}
		},
		repositoryRetryDelay: func(int) time.Duration { return 0 },
	}

	if err := a.Sync(ctx); err == nil {
		t.Fatal("Sync succeeded, want cancellation error")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("Sync calls = %d, want 1", got)
	}
}

func TestVerifyAndPruneAreIsolatedButNotRetried(t *testing.T) {
	var verifyCalls atomic.Int32
	var pruneCalls atomic.Int32
	a := &App{
		Config: &config.Config{Sync: config.Sync{RepositoryRetries: 2}},
		repoRunnersOverride: func() []repoTask {
			return []repoTask{
				{
					label: "apt/ubuntu",
					runner: &fakeRunner{
						verifyFn: func(context.Context) error {
							verifyCalls.Add(1)
							return errors.New("verify failed")
						},
						pruneFn: func(context.Context) ([]string, error) {
							pruneCalls.Add(1)
							return nil, errors.New("prune failed")
						},
					},
				},
				{
					label: "apk/alpine",
					runner: &fakeRunner{
						verifyFn: func(context.Context) error {
							verifyCalls.Add(1)
							return nil
						},
						pruneFn: func(context.Context) ([]string, error) {
							pruneCalls.Add(1)
							return nil, nil
						},
					},
				},
			}
		},
		repositoryRetryDelay: func(int) time.Duration {
			t.Fatal("verify/prune should not use repository retry delay")
			return 0
		},
	}

	if err := a.Verify(context.Background()); err == nil || !strings.Contains(err.Error(), "apt/ubuntu") {
		t.Fatalf("Verify error = %v, want labeled verify failure", err)
	}
	if err := a.Prune(context.Background()); err == nil || !strings.Contains(err.Error(), "apt/ubuntu") {
		t.Fatalf("Prune error = %v, want labeled prune failure", err)
	}
	if got := verifyCalls.Load(); got != 2 {
		t.Fatalf("Verify calls = %d, want one call per repository", got)
	}
	if got := pruneCalls.Load(); got != 2 {
		t.Fatalf("Prune calls = %d, want one call per repository", got)
	}
}

func TestRepoRetryDelayIsLinearByDefault(t *testing.T) {
	a := &App{}
	for retry := 1; retry <= 3; retry++ {
		if got, want := a.repoRetryDelay(retry), time.Duration(retry)*time.Second; got != want {
			t.Fatalf("retry delay %d = %v, want %v", retry, got, want)
		}
	}
}

func TestRunRepoWithRetriesLabelsFinalFailure(t *testing.T) {
	a := &App{repositoryRetryDelay: func(int) time.Duration { return 0 }}
	runner := &fakeRunner{syncFn: func(context.Context) error { return fmt.Errorf("failed") }}
	err := a.runRepoWithRetries(context.Background(), repoTask{label: "apt/ubuntu", runner: runner}, 1, func(ctx context.Context, r repoRunner) error {
		return r.Sync(ctx)
	})
	if err == nil || !strings.Contains(err.Error(), "apt/ubuntu") {
		t.Fatalf("error = %v, want labeled failure", err)
	}
}
