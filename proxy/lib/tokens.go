package snowflake_proxy

import (
	"sync"
)

type tokens_t struct {
	sync.RWMutex
	clients int64
}

func newTokens() *tokens_t {
	return &tokens_t{
		clients: 0,
	}
}

func (t *tokens_t) get() {
	t.Lock()
	t.clients += 1
	t.Unlock()
}

func (t *tokens_t) ret() {
	t.Lock()
	t.clients -= 1
	t.Unlock()
}

func (t *tokens_t) count() int64 {
	t.RLock()
	clients := t.clients
	t.RUnlock()
	return clients
}
