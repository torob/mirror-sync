package limit

import "context"

type Limiter struct {
	ch chan struct{}
}

func New(max int) *Limiter {
	if max <= 0 {
		return nil
	}
	return &Limiter{ch: make(chan struct{}, max)}
}

func (l *Limiter) Acquire(ctx context.Context) (func(), error) {
	if l == nil {
		return func() {}, nil
	}
	select {
	case l.ch <- struct{}{}:
		return func() { <-l.ch }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
