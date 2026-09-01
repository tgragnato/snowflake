package task

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// currentInterval reads the next scheduled interval under the task's lock.
func currentInterval(t *ExpBackoff) time.Duration {
	t.access.Lock()
	defer t.access.Unlock()

	return t.interval
}

// TestExpBackoffIntervalProgression drives checkedExecute by hand to check the
// doubling schedule. Both intervals are far longer than the test, so the timers
// that checkedExecute schedules never fire and cannot race with the assertions.
func TestExpBackoffIntervalProgression(t *testing.T) {
	t.Parallel()

	const (
		minInterval = time.Hour
		maxInterval = 10 * time.Hour
	)

	var fail atomic.Bool
	task := &ExpBackoff{
		MinInterval: minInterval,
		MaxInterval: maxInterval,
		Execute: func() error {
			if fail.Load() {
				return errors.New("execute failed")
			}
			return nil
		},
		OnError: func(error) {},
	}

	// A successful first run waits MaxInterval.
	if err := task.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer task.Close()
	if got := currentInterval(task); got != maxInterval {
		t.Fatalf("after success: got %v, want MaxInterval %v", got, maxInterval)
	}

	// The first failure drops the interval to MinInterval, then each
	// subsequent failure doubles it, saturating at MaxInterval.
	fail.Store(true)
	for i, want := range []time.Duration{
		minInterval,
		2 * minInterval,
		4 * minInterval,
		8 * minInterval,
		maxInterval, // 16h would exceed MaxInterval
		maxInterval, // and it stays there
	} {
		if err := task.checkedExecute(); err != nil {
			t.Fatalf("failure %d: checkedExecute: %v", i, err)
		}
		if got := currentInterval(task); got != want {
			t.Fatalf("failure %d: got %v, want %v", i, got, want)
		}
	}

	// A success resets the failure streak, so the next failure starts over
	// from MinInterval rather than continuing to double.
	fail.Store(false)
	if err := task.checkedExecute(); err != nil {
		t.Fatalf("checkedExecute after recovery: %v", err)
	}
	fail.Store(true)
	if err := task.checkedExecute(); err != nil {
		t.Fatalf("checkedExecute after relapse: %v", err)
	}
	if got := currentInterval(task); got != minInterval {
		t.Errorf("after a success then a failure: got %v, want MinInterval %v", got, minInterval)
	}
}

func TestExpBackoffRunsRepeatedly(t *testing.T) {
	t.Parallel()

	ticks := make(chan struct{}, 16)
	task := &ExpBackoff{
		MinInterval: time.Millisecond,
		MaxInterval: time.Millisecond,
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

	for range 3 {
		waitFor(t, ticks, "execution")
	}
}

func TestExpBackoffStartIsIdempotent(t *testing.T) {
	t.Parallel()

	started := make(chan struct{}, 8)
	task := &ExpBackoff{
		MinInterval: time.Hour,
		MaxInterval: time.Hour,
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

	if err := task.Start(); err != nil {
		t.Fatalf("second Start: %v", err)
	}
	select {
	case <-started:
		t.Fatal("Start executed the task a second time while it was already running")
	case <-time.After(50 * time.Millisecond):
	}
}

func TestExpBackoffErrorWithoutOnErrorStopsTask(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("execute failed")
	var calls atomic.Int32
	task := &ExpBackoff{
		MinInterval: time.Millisecond,
		MaxInterval: time.Millisecond,
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

func TestExpBackoffErrorWithOnErrorKeepsRunning(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("execute failed")
	errs := make(chan error, 16)
	task := &ExpBackoff{
		MinInterval: time.Millisecond,
		MaxInterval: 2 * time.Millisecond,
		Execute:     func() error { return wantErr },
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

	for range 2 {
		if got := waitFor(t, errs, "OnError"); !errors.Is(got, wantErr) {
			t.Fatalf("expected %v, got %v", wantErr, got)
		}
	}
	if task.hasClosed() {
		t.Error("a task with an OnError handler must keep running after a failure")
	}
}

func TestExpBackoffCloseStopsExecution(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	ticks := make(chan struct{}, 16)
	task := &ExpBackoff{
		MinInterval: 5 * time.Millisecond,
		MaxInterval: 5 * time.Millisecond,
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

	time.Sleep(30 * time.Millisecond)
	settled := calls.Load()
	time.Sleep(30 * time.Millisecond)
	if got := calls.Load(); got != settled {
		t.Errorf("task kept executing after Close: %d then %d", settled, got)
	}
}

func TestExpBackoffCloseIsIdempotent(t *testing.T) {
	t.Parallel()

	task := &ExpBackoff{
		MinInterval: time.Hour,
		MaxInterval: time.Hour,
		Execute:     func() error { return nil },
	}

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

func TestExpBackoffCheckedExecuteSkipsWhenClosed(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	task := &ExpBackoff{
		MinInterval: time.Hour,
		MaxInterval: time.Hour,
		Execute:     func() error { calls.Add(1); return nil },
	}

	if err := task.checkedExecute(); err != nil {
		t.Fatalf("checkedExecute: %v", err)
	}
	if got := calls.Load(); got != 0 {
		t.Errorf("expected no execution on a closed task, got %d", got)
	}
}

func TestExpBackoffWaitThenStart(t *testing.T) {
	t.Parallel()

	ticks := make(chan struct{}, 16)
	task := &ExpBackoff{
		MinInterval: time.Millisecond,
		MaxInterval: time.Millisecond,
		Execute: func() error {
			select {
			case ticks <- struct{}{}:
			default:
			}
			return nil
		},
	}

	task.WaitThenStart()
	defer task.Close()

	waitFor(t, ticks, "the deferred first execution")
}
