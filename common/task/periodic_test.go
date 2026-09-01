package task

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// waitFor reads one value from ch, failing the test if nothing arrives.
// Tests synchronise on the task's own execution rather than sleeping.
func waitFor[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()

	select {
	case v := <-ch:
		return v
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
		panic("unreachable")
	}
}

func TestPeriodicInvalidInterval(t *testing.T) {
	t.Parallel()

	for _, interval := range []time.Duration{0, -time.Second} {
		task := &Periodic{
			Interval: interval,
			Execute:  func() error { t.Error("Execute must not run with an invalid interval"); return nil },
		}
		if err := task.Start(); err == nil {
			t.Errorf("interval %v: expected an error", interval)
		}
		if !task.hasClosed() {
			t.Errorf("interval %v: task must not be running", interval)
		}
	}
}

func TestPeriodicRunsRepeatedly(t *testing.T) {
	t.Parallel()

	ticks := make(chan struct{}, 16)
	task := &Periodic{
		Interval: time.Millisecond,
		Execute: func() error {
			select {
			case ticks <- struct{}{}:
			default:
			}
			return nil
		},
	}

	if err := task.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer task.Close()

	// The first execution is synchronous, the rest come from the timer.
	for range 3 {
		waitFor(t, ticks, "execution")
	}
}

func TestPeriodicStartIsIdempotent(t *testing.T) {
	t.Parallel()

	started := make(chan struct{}, 8)
	task := &Periodic{
		Interval: time.Hour,
		Execute: func() error {
			started <- struct{}{}
			return nil
		},
	}

	if err := task.Start(); err != nil {
		t.Fatalf("first Start: %v", err)
	}
	defer task.Close()
	waitFor(t, started, "the first execution")

	// A second Start on a running task must not execute again.
	if err := task.Start(); err != nil {
		t.Fatalf("second Start: %v", err)
	}
	select {
	case <-started:
		t.Fatal("Start executed the task a second time while it was already running")
	case <-time.After(50 * time.Millisecond):
	}
}

func TestPeriodicErrorWithoutOnErrorStopsTask(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("execute failed")
	var calls atomic.Int32
	task := &Periodic{
		Interval: time.Millisecond,
		Execute: func() error {
			calls.Add(1)
			return wantErr
		},
	}

	if err := task.Start(); !errors.Is(err, wantErr) {
		t.Fatalf("expected %v, got %v", wantErr, err)
	}
	if !task.hasClosed() {
		t.Error("a task that failed without an OnError handler must stop running")
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("expected exactly 1 execution, got %d", got)
	}
}

func TestPeriodicErrorWithOnErrorKeepsRunning(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("execute failed")
	errs := make(chan error, 16)
	task := &Periodic{
		Interval: time.Millisecond,
		Execute:  func() error { return wantErr },
		OnError: func(err error) {
			select {
			case errs <- err:
			default:
			}
		},
	}

	if err := task.Start(); err != nil {
		t.Fatalf("Start must not return the error when OnError is set, got %v", err)
	}
	defer task.Close()

	// OnError handles the failure and the task stays scheduled.
	for range 2 {
		if got := waitFor(t, errs, "OnError"); !errors.Is(got, wantErr) {
			t.Fatalf("expected %v, got %v", wantErr, got)
		}
	}
	if task.hasClosed() {
		t.Error("a task with an OnError handler must keep running after a failure")
	}
}

func TestPeriodicCloseStopsExecution(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	ticks := make(chan struct{}, 16)
	task := &Periodic{
		Interval: 5 * time.Millisecond,
		Execute: func() error {
			calls.Add(1)
			select {
			case ticks <- struct{}{}:
			default:
			}
			return nil
		},
	}

	if err := task.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	waitFor(t, ticks, "the first execution")

	if err := task.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !task.hasClosed() {
		t.Fatal("hasClosed must report true after Close")
	}

	// Allow any in-flight timer to fire, then confirm the count is stable.
	time.Sleep(30 * time.Millisecond)
	settled := calls.Load()
	time.Sleep(30 * time.Millisecond)
	if got := calls.Load(); got != settled {
		t.Errorf("task kept executing after Close: %d then %d", settled, got)
	}
}

func TestPeriodicCloseIsIdempotent(t *testing.T) {
	t.Parallel()

	task := &Periodic{Interval: time.Hour, Execute: func() error { return nil }}

	// Close before Start must not panic on the nil timer.
	if err := task.Close(); err != nil {
		t.Fatalf("Close before Start: %v", err)
	}
	if err := task.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := task.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := task.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestPeriodicCheckedExecuteSkipsWhenClosed(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	task := &Periodic{
		Interval: time.Hour,
		Execute:  func() error { calls.Add(1); return nil },
	}

	// Never started, so the task counts as closed.
	if err := task.checkedExecute(); err != nil {
		t.Fatalf("checkedExecute: %v", err)
	}
	if got := calls.Load(); got != 0 {
		t.Errorf("expected no execution on a closed task, got %d", got)
	}
}

func TestPeriodicWaitThenStart(t *testing.T) {
	t.Parallel()

	ticks := make(chan struct{}, 16)
	task := &Periodic{
		Interval: time.Millisecond,
		Execute: func() error {
			select {
			case ticks <- struct{}{}:
			default:
			}
			return nil
		},
	}

	// WaitThenStart defers the first execution by one interval.
	task.WaitThenStart()
	defer task.Close()

	waitFor(t, ticks, "the deferred first execution")
}
