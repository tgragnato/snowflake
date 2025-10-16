package event

import (
	"testing"
)

type stubReceiver struct {
	counter int
}

func (s *stubReceiver) OnNewSnowflakeEvent(event SnowflakeEvent) {
	s.counter++
}

func TestBusDispatch(t *testing.T) {
	t.Parallel()

	EventBus := NewSnowflakeEventDispatcher()
	StubReceiverA := &stubReceiver{}
	StubReceiverB := &stubReceiver{}
	EventBus.AddSnowflakeEventListener(StubReceiverA)
	EventBus.AddSnowflakeEventListener(StubReceiverB)
	if StubReceiverA.counter != 0 {
		t.Fatalf("expected StubReceiverA.counter == 0, got %d", StubReceiverA.counter)
	}
	if StubReceiverB.counter != 0 {
		t.Fatalf("expected StubReceiverB.counter == 0, got %d", StubReceiverB.counter)
	}
	EventBus.OnNewSnowflakeEvent(EventOnSnowflakeConnected{})
	if StubReceiverA.counter != 1 {
		t.Fatalf("expected StubReceiverA.counter == 1, got %d", StubReceiverA.counter)
	}
	if StubReceiverB.counter != 1 {
		t.Fatalf("expected StubReceiverB.counter == 1, got %d", StubReceiverB.counter)
	}
	EventBus.RemoveSnowflakeEventListener(StubReceiverB)
	EventBus.OnNewSnowflakeEvent(EventOnSnowflakeConnected{})
	if StubReceiverA.counter != 2 {
		t.Fatalf("expected StubReceiverA.counter == 2, got %d", StubReceiverA.counter)
	}
	if StubReceiverB.counter != 1 {
		t.Fatalf("expected StubReceiverB.counter == 1, got %d", StubReceiverB.counter)
	}
}
