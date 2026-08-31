// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package authn

import "sync"

// lruCache is a bounded least-recently-used map.
//
// It is written here rather than pulled in as a dependency because the
// dependency budget for this project is a closed set, and because the eviction
// policy is load bearing: the cache holds one entry per live credential and
// must not be allowed to grow with the number of *attempted* credentials, or
// an attacker could evict every real entry by presenting garbage.
//
// Entries carry no expiry of their own; time-based invalidation is the
// caller's business, because the two caches in this package expire on
// different clocks.
//
// All methods are safe for concurrent use.
type lruCache[K comparable, V any] struct {
	mu   sync.Mutex
	cap  int
	m    map[K]*lruNode[K, V]
	head *lruNode[K, V] // most recently used
	tail *lruNode[K, V] // least recently used
}

// lruNode is one entry in the intrusive doubly linked recency list.
type lruNode[K comparable, V any] struct {
	key        K
	val        V
	prev, next *lruNode[K, V]
}

// newLRU returns a cache holding at most capacity entries. A capacity below 1
// is raised to 1, so the cache is never a silent no-op that would turn every
// lookup into a store round trip.
func newLRU[K comparable, V any](capacity int) *lruCache[K, V] {
	if capacity < 1 {
		capacity = 1
	}
	return &lruCache[K, V]{cap: capacity, m: make(map[K]*lruNode[K, V], capacity)}
}

// Get returns the value stored under key and marks it most recently used.
func (c *lruCache[K, V]) Get(key K) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n, ok := c.m[key]
	if !ok {
		var zero V
		return zero, false
	}
	c.moveToFront(n)
	return n.val, true
}

// Put inserts or replaces the value under key, evicting the least recently
// used entry when the cache is full.
func (c *lruCache[K, V]) Put(key K, val V) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if n, ok := c.m[key]; ok {
		n.val = val
		c.moveToFront(n)
		return
	}
	n := &lruNode[K, V]{key: key, val: val}
	c.m[key] = n
	c.pushFront(n)
	for len(c.m) > c.cap {
		c.evictTail()
	}
}

// Remove deletes key if present and reports whether it was there.
func (c *lruCache[K, V]) Remove(key K) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	n, ok := c.m[key]
	if !ok {
		return false
	}
	c.unlink(n)
	delete(c.m, key)
	return true
}

// Purge drops every entry. It is what a revocation-epoch bump triggers: one
// counter change invalidates the whole cache rather than requiring a scan.
func (c *lruCache[K, V]) Purge() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m = make(map[K]*lruNode[K, V], c.cap)
	c.head, c.tail = nil, nil
}

// pushFront links n at the most-recently-used end. The caller holds c.mu.
func (c *lruCache[K, V]) pushFront(n *lruNode[K, V]) {
	n.prev = nil
	n.next = c.head
	if c.head != nil {
		c.head.prev = n
	}
	c.head = n
	if c.tail == nil {
		c.tail = n
	}
}

// unlink removes n from the recency list. The caller holds c.mu.
func (c *lruCache[K, V]) unlink(n *lruNode[K, V]) {
	if n.prev != nil {
		n.prev.next = n.next
	} else {
		c.head = n.next
	}
	if n.next != nil {
		n.next.prev = n.prev
	} else {
		c.tail = n.prev
	}
	n.prev, n.next = nil, nil
}

// moveToFront marks n most recently used. The caller holds c.mu.
func (c *lruCache[K, V]) moveToFront(n *lruNode[K, V]) {
	if c.head == n {
		return
	}
	c.unlink(n)
	c.pushFront(n)
}

// evictTail drops the least recently used entry. The caller holds c.mu.
func (c *lruCache[K, V]) evictTail() {
	n := c.tail
	c.unlink(n)
	delete(c.m, n.key)
}
