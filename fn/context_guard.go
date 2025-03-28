package fn

import (
	"context"
	"sync"
	"time"
)

// ContextGuard is an embeddable struct that provides a wait group and main quit
// channel that can be used to create guarded contexts.
type ContextGuard struct {
	DefaultTimeout time.Duration
	Wg             sync.WaitGroup
	Quit           chan struct{}
}

// WithCtxQuit is used to create a cancellable context that will be cancelled
// if the main quit signal is triggered or after the default timeout occurred.
func (g *ContextGuard) WithCtxQuit() (context.Context, func()) {
	return g.WithCtxQuitCustomTimeout(g.DefaultTimeout)
}

// WithCtxQuitCustomTimeout is used to create a cancellable context that will be
// cancelled if the main quit signal is triggered or after the given timeout
// occurred.
func (g *ContextGuard) WithCtxQuitCustomTimeout(
	timeout time.Duration) (context.Context, func()) {

	timeoutTimer := time.NewTimer(timeout)
	ctx, cancel := context.WithCancel(context.Background())

	g.Wg.Add(1)
	go func() {
		defer timeoutTimer.Stop()
		defer cancel()
		defer g.Wg.Done()

		select {
		case <-g.Quit:

		case <-timeoutTimer.C:

		case <-ctx.Done():
		}
	}()

	return ctx, cancel
}

// CtxBlocking is used to create a cancellable context that will NOT be
// cancelled if the main quit signal is triggered, to block shutdown of
// important tasks. The context will be cancelled if the timeout is reached.
func (g *ContextGuard) CtxBlocking() (context.Context, func()) {
	return g.CtxBlockingCustomTimeout(g.DefaultTimeout)
}

// CtxBlockingCustomTimeout is used to create a cancellable context with a
// custom timeout that will NOT be cancelled if the main quit signal is
// triggered, to block shutdown of important tasks. The context will be
// cancelled if the timeout is reached.
func (g *ContextGuard) CtxBlockingCustomTimeout(
	timeout time.Duration) (context.Context, func()) {

	timeoutTimer := time.NewTimer(timeout)
	ctx, cancel := context.WithCancel(context.Background())

	g.Wg.Add(1)
	go func() {
		defer timeoutTimer.Stop()
		defer cancel()
		defer g.Wg.Done()

		select {
		case <-timeoutTimer.C:

		case <-ctx.Done():
		}
	}()

	return ctx, cancel
}

// WithCtxQuitNoTimeout is used to create a cancellable context that will be
// cancelled if the main quit signal is triggered.
func (g *ContextGuard) WithCtxQuitNoTimeout() (context.Context, func()) {
	ctx, cancel := context.WithCancel(context.Background())

	g.Wg.Add(1)
	go func() {
		defer cancel()
		defer g.Wg.Done()

		select {
		case <-g.Quit:

		case <-ctx.Done():
		}
	}()

	return ctx, cancel
}

// Goroutine runs the given function in a separate goroutine and ensures proper
// error handling. If the object function returns an error, the provided error
// handler is called.
//
// This method also manages the context guard wait group when spawning the
// goroutine.
func (g *ContextGuard) Goroutine(f func() error, errHandler func(error)) {
	if f == nil {
		panic("no function provided")
	}

	if errHandler == nil {
		panic("no error handler provided")
	}

	g.Wg.Add(1)
	go func() {
		defer g.Wg.Done()

		err := f()
		if err != nil {
			errHandler(err)
		}
	}()
}
