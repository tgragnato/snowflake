/*
Keeping track of pending available snowflake proxies.
*/

package main

import (
	"container/heap"
	"sync"
	"time"
)

/*
The Snowflake struct contains a single interaction
over the offer and answer channels.
*/
type Snowflake struct {
	id            string
	proxyType     string
	natType       string
	offerChannel  chan *ClientOffer
	answerChannel chan string
	clients       uint64
	index         int
}

func NewSnowflake(id string, proxyType string, natType string, clients uint64) *Snowflake {
	snowflake := new(Snowflake)
	snowflake.id = id
	snowflake.clients = clients
	snowflake.proxyType = proxyType
	snowflake.natType = natType
	snowflake.offerChannel = make(chan *ClientOffer)
	snowflake.answerChannel = make(chan string)
	return snowflake
}

// Implements heap.Interface, and holds Snowflakes.
type SnowflakeHeap []*Snowflake

func (sh SnowflakeHeap) Len() int { return len(sh) }

func (sh SnowflakeHeap) Less(i, j int) bool {
	// Snowflakes serving less clients should sort earlier.
	return sh[i].clients < sh[j].clients
}

func (sh SnowflakeHeap) Swap(i, j int) {
	sh[i], sh[j] = sh[j], sh[i]
	sh[i].index = i
	sh[j].index = j
}

func (sh *SnowflakeHeap) Push(s interface{}) {
	n := len(*sh)
	snowflake := s.(*Snowflake)
	snowflake.index = n
	*sh = append(*sh, snowflake)
}

// Only valid when Len() > 0.
func (sh *SnowflakeHeap) Pop() interface{} {
	flakes := *sh
	n := len(flakes)
	snowflake := flakes[n-1]
	snowflake.index = -1
	*sh = flakes[0 : n-1]
	return snowflake
}

type SnowflakePool struct {
	h            *SnowflakeHeap
	lock         sync.Mutex
	pollInterval time.Duration
}

func NewSnowflakePool() *SnowflakePool {
	h := new(SnowflakeHeap)
	heap.Init(h)
	return &SnowflakePool{
		h:            h,
		pollInterval: 20 * time.Second,
	}
}

func (sp *SnowflakePool) Push(s *Snowflake) {
	sp.lock.Lock()
	defer sp.lock.Unlock()
	heap.Push(sp.h, s)
}

func (sp *SnowflakePool) Pop() *Snowflake {
	sp.lock.Lock()
	defer sp.lock.Unlock()
	if sp.h.Len() > 0 {
		return heap.Pop(sp.h).(*Snowflake)
	}
	return nil
}

func (sp *SnowflakePool) Remove(s *Snowflake) {
	sp.lock.Lock()
	defer sp.lock.Unlock()
	if s.index != -1 {
		heap.Remove(sp.h, s.index)
	}
}

func (sp *SnowflakePool) GetPollInterval() time.Duration {
	sp.lock.Lock()
	defer sp.lock.Unlock()
	return sp.pollInterval
}

func (sp *SnowflakePool) SetPollInterval(interval time.Duration) {
	sp.lock.Lock()
	defer sp.lock.Unlock()
	sp.pollInterval = interval
}
