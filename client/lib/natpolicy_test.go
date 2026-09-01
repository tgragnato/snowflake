package snowflake_client

import (
	"testing"

	"tgragnato.it/snowflake/common/nat"
)

// While our own NAT type is unknown, the client claims to be unrestricted so
// that it is matched with a restricted proxy, leaving the scarce unrestricted
// proxies for the clients that actually need them.
func TestNATPolicySpoofsWhileNATTypeIsUnknown(t *testing.T) {
	t.Parallel()

	policy := &NATPolicy{}

	if got := policy.NATTypeToSend(nat.NATUnknown); got != nat.NATUnrestricted {
		t.Errorf("got %q, want %q", got, nat.NATUnrestricted)
	}
}

// A known NAT type is always reported as-is: spoofing it would get the client
// matched with a proxy it cannot talk to.
func TestNATPolicyDoesNotSpoofKnownNATTypes(t *testing.T) {
	t.Parallel()

	for _, natType := range []string{
		nat.NATUnrestricted,
		nat.NATRestricted,
		nat.NAT3Open,
		nat.NAT3Moderate,
		nat.NAT3Strict,
	} {
		policy := &NATPolicy{}
		if got := policy.NATTypeToSend(natType); got != natType {
			t.Errorf("NAT type %q: got %q, want it unchanged", natType, got)
		}
	}
}

// Once a spoofed attempt has failed, the client must stop spoofing, otherwise
// it would keep being matched with proxies it cannot reach.
func TestNATPolicyStopsSpoofingAfterFailure(t *testing.T) {
	t.Parallel()

	policy := &NATPolicy{}

	sent := policy.NATTypeToSend(nat.NATUnknown)
	if sent != nat.NATUnrestricted {
		t.Fatalf("first attempt: got %q, want %q", sent, nat.NATUnrestricted)
	}

	policy.Failure(nat.NATUnknown, sent)

	if got := policy.NATTypeToSend(nat.NATUnknown); got != nat.NATUnknown {
		t.Errorf("after a failed spoofed attempt: got %q, want %q", got, nat.NATUnknown)
	}
}

// Only the spoofed combination is evidence that spoofing does not work. A
// failure while reporting the truth says nothing about the policy.
func TestNATPolicyFailureWithoutSpoofingKeepsSpoofing(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name               string
		actualNAT, sentNAT string
	}{
		{"no spoofing took place", nat.NATUnknown, nat.NATUnknown},
		{"our NAT type is known", nat.NATRestricted, nat.NATRestricted},
		{"a known type was reported", nat.NATUnrestricted, nat.NATUnrestricted},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			policy := &NATPolicy{}
			policy.Failure(test.actualNAT, test.sentNAT)

			if got := policy.NATTypeToSend(nat.NATUnknown); got != nat.NATUnrestricted {
				t.Errorf("got %q, want %q", got, nat.NATUnrestricted)
			}
		})
	}
}

// Repeated failures must not resurrect spoofing.
func TestNATPolicyFailureIsSticky(t *testing.T) {
	t.Parallel()

	policy := &NATPolicy{}
	policy.Failure(nat.NATUnknown, nat.NATUnrestricted)
	policy.Failure(nat.NATUnknown, nat.NATUnknown)

	if got := policy.NATTypeToSend(nat.NATUnknown); got != nat.NATUnknown {
		t.Errorf("got %q, want %q", got, nat.NATUnknown)
	}
}

// Success only reports; it must not change what the policy sends next.
func TestNATPolicySuccessDoesNotChangePolicy(t *testing.T) {
	t.Parallel()

	t.Run("after a spoofed success", func(t *testing.T) {
		t.Parallel()

		policy := &NATPolicy{}
		policy.Success(nat.NATUnknown, nat.NATUnrestricted)

		if got := policy.NATTypeToSend(nat.NATUnknown); got != nat.NATUnrestricted {
			t.Errorf("got %q, want %q", got, nat.NATUnrestricted)
		}
	})

	t.Run("after a success following a failure", func(t *testing.T) {
		t.Parallel()

		policy := &NATPolicy{}
		policy.Failure(nat.NATUnknown, nat.NATUnrestricted)
		policy.Success(nat.NATUnknown, nat.NATUnknown)

		if got := policy.NATTypeToSend(nat.NATUnknown); got != nat.NATUnknown {
			t.Errorf("got %q, want %q", got, nat.NATUnknown)
		}
	})
}

// The policy is consulted and updated from several connection attempts at
// once, so it has to be safe to use concurrently.
func TestNATPolicyConcurrentUse(t *testing.T) {
	t.Parallel()

	policy := &NATPolicy{}
	done := make(chan struct{})

	for range 8 {
		go func() {
			defer func() { done <- struct{}{} }()
			for range 100 {
				sent := policy.NATTypeToSend(nat.NATUnknown)
				policy.Success(nat.NATUnknown, sent)
				policy.Failure(nat.NATUnknown, sent)
			}
		}()
	}
	for range 8 {
		<-done
	}

	// Every goroutine reported a failure, so spoofing must be off.
	if got := policy.NATTypeToSend(nat.NATUnknown); got != nat.NATUnknown {
		t.Errorf("got %q, want %q", got, nat.NATUnknown)
	}
}

func TestWebRTCDialerGetMax(t *testing.T) {
	t.Parallel()

	for _, max := range []int{1, 3} {
		dialer := NewWebRTCDialer(&BrokerChannel{}, nil, max)
		if got := dialer.GetMax(); got != max {
			t.Errorf("got %d, want %d", got, max)
		}
	}
}
