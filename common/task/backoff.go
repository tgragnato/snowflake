// Package task
// Reused from https://github.com/v2fly/v2ray-core/blob/784775f68922f07d40c9eead63015b2026af2ade/common/task/periodic.go
/*
The MIT License (MIT)

Copyright (c) 2015-2021 V2Ray & V2Fly Community
Copyright (c) 2026 The Tor Project, Inc

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
package task

import (
	"sync"
	"time"
)

// ExpBackoff is a task that runs periodically. When the task succeeds,
// the next run occurs at MaxInterval. When the task fails, the next
// run is scheduled in MinInterval. For each subsequent failure, the interval
// is doubled until MaxInterval is reached
type ExpBackoff struct {
	// Interval of the task being run
	MinInterval time.Duration
	// MaxInterval longest duration to wait between tasks
	MaxInterval time.Duration
	// Execute is the task function
	Execute func() error
	// OnError handles the error of the task
	OnError func(error)

	failed   bool
	interval time.Duration
	access   sync.Mutex
	timer    *time.Timer
	running  bool
}

func (t *ExpBackoff) hasClosed() bool {
	t.access.Lock()
	defer t.access.Unlock()

	return !t.running
}

func (t *ExpBackoff) checkedExecute() error {
	if t.hasClosed() {
		return nil
	}

	err := t.Execute()
	if err != nil {
		if t.OnError != nil {
			t.OnError(err)
		} else {
			// default error handling is to shut down the task
			t.access.Lock()
			t.running = false
			t.access.Unlock()
			return err
		}
		// increase interval unless we've reached MaxInterval
		if t.failed {
			t.interval = min(t.interval*2, t.MaxInterval)
		} else {
			t.failed = true
			t.interval = t.MinInterval
		}
	} else {
		t.failed = false
	}

	t.access.Lock()
	defer t.access.Unlock()

	if !t.running {
		return nil
	}

	t.timer = time.AfterFunc(t.interval, func() {
		t.checkedExecute()
	})

	return nil
}

// Start implements common.Runnable.
func (t *ExpBackoff) Start() error {
	t.access.Lock()
	t.interval = t.MaxInterval
	if t.running {
		t.access.Unlock()
		return nil
	}
	t.running = true
	t.access.Unlock()

	return t.checkedExecute()
}

func (t *ExpBackoff) WaitThenStart() {
	time.AfterFunc(t.MinInterval, func() {
		t.Start()
	})
}

// Close implements common.Closable.
func (t *ExpBackoff) Close() error {
	t.access.Lock()
	defer t.access.Unlock()

	t.running = false
	if t.timer != nil {
		t.timer.Stop()
		t.timer = nil
	}

	return nil
}
