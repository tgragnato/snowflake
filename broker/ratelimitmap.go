package main

import (
	"container/heap"
	"crypto/hmac"
	"crypto/rand"
	"hash"
	"sync"
	"time"

	"golang.org/x/crypto/sha3"
)

type proxyRecord struct {
	AddrHash     [32]byte
	NoSoonerThan time.Time
}

type RateLimitMap struct {
	key   []byte
	inner *rateLimitMapInner
	lock  sync.Mutex
}

func NewRateLimitMap() *RateLimitMap {
	var ipMaskingKey [32]byte
	if n, err := rand.Read(ipMaskingKey[:]); (n < 32) || (err != nil) {
		panic(err)
	}
	m := &RateLimitMap{
		key: ipMaskingKey[:],
		inner: &rateLimitMapInner{
			byAge:  make([]*proxyRecord, 0),
			byAddr: make(map[[32]byte]int),
		},
	}
	go func() {
		for {
			time.Sleep(2 * time.Second)
			now := time.Now()
			m.lock.Lock()
			m.inner.removeExpired(now)
			m.lock.Unlock()
		}
	}()

	return m
}

// Lookup checks the RateLimitMap and returns a timestamp if available
// and a boolean indicating whether or one was found
func (m *RateLimitMap) Lookup(addr string) (time.Time, bool) {
	hash := hashAddr(m.key, addr)
	m.lock.Lock()
	defer m.lock.Unlock()
	i, ok := m.inner.byAddr[hash]
	if ok {
		return m.inner.byAge[i].NoSoonerThan, true
	}
	return time.Now(), false
}

func (m *RateLimitMap) Add(addr string, noSoonerThan time.Time) {
	m.lock.Lock()
	m.inner.Add(hashAddr(m.key, addr), noSoonerThan)
	m.lock.Unlock()
}

func hashAddr(key []byte, addr string) [32]byte {
	hmacIPMasker := hmac.New(func() hash.Hash {
		return sha3.New256()
	}, key)
	hmacIPMasker.Write([]byte(addr))
	return [32]byte(hmacIPMasker.Sum(nil))
}

// rateLimitMapInner is the inner type of RateLimitMap, inspired by
// clientMapInner. Implements heap.Interface and requires external
// synchronization
type rateLimitMapInner struct {
	byAge  []*proxyRecord
	byAddr map[[32]byte]int
}

func (inner *rateLimitMapInner) Add(haddr [32]byte, noSoonerThan time.Time) {
	record := &proxyRecord{
		AddrHash:     haddr,
		NoSoonerThan: noSoonerThan,
	}
	if i, ok := inner.byAddr[record.AddrHash]; ok {
		// Found one, update its LastSeen.
		record = inner.byAge[i]
		record.NoSoonerThan = noSoonerThan
		heap.Fix(inner, i)
		return
	}
	heap.Push(inner, record)
}

// removeExpired removes all rate limit map entries whose noSoonerThan
// timestamp has already passed.
func (inner *rateLimitMapInner) removeExpired(now time.Time) {
	for len(inner.byAge) > 0 && inner.byAge[0].NoSoonerThan.Before(now) {
		heap.Pop(inner)
	}
}

// heap.Interface for rateLimitMapInner.

func (inner *rateLimitMapInner) Len() int {
	if len(inner.byAge) != len(inner.byAddr) {
		panic("inconsistent rateLimitMap")
	}
	return len(inner.byAge)
}

func (inner *rateLimitMapInner) Less(i, j int) bool {
	return inner.byAge[i].NoSoonerThan.Before(inner.byAge[j].NoSoonerThan)
}

func (inner *rateLimitMapInner) Swap(i, j int) {
	inner.byAge[i], inner.byAge[j] = inner.byAge[j], inner.byAge[i]
	inner.byAddr[inner.byAge[i].AddrHash] = i
	inner.byAddr[inner.byAge[j].AddrHash] = j
}

func (inner *rateLimitMapInner) Push(x any) {
	record := x.(*proxyRecord)
	if _, ok := inner.byAddr[record.AddrHash]; ok {
		panic("duplicate address in rateLimitMap")
	}
	// Insert into byAddr map.
	inner.byAddr[record.AddrHash] = len(inner.byAge)
	// Insert into byAge slice.
	inner.byAge = append(inner.byAge, record)
}

func (inner *rateLimitMapInner) Pop() any {
	n := len(inner.byAddr)
	// Remove from byAge slice.
	record := inner.byAge[n-1]
	inner.byAge[n-1] = nil
	inner.byAge = inner.byAge[:n-1]
	// Remove from byAddr map.
	delete(inner.byAddr, record.AddrHash)
	return record
}
