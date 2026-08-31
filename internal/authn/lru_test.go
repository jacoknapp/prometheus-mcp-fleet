// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package authn

import (
	"strconv"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestLRUEviction(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		// ops is applied to a cache of capacity 3.
		ops  func(c *lruCache[string, int])
		want []string // keys expected to remain, any order
	}{
		{
			name: "capacity below one is raised",
			ops: func(c *lruCache[string, int]) {
				c.Put("a", 1)
			},
			want: []string{"a"},
		},
		{
			name: "oldest is evicted",
			ops: func(c *lruCache[string, int]) {
				c.Put("a", 1)
				c.Put("b", 2)
				c.Put("c", 3)
				c.Put("d", 4)
			},
			want: []string{"b", "c", "d"},
		},
		{
			name: "a read protects an entry",
			ops: func(c *lruCache[string, int]) {
				c.Put("a", 1)
				c.Put("b", 2)
				c.Put("c", 3)
				c.Get("a")
				c.Put("d", 4)
			},
			want: []string{"a", "c", "d"},
		},
		{
			name: "replacing refreshes recency without growing",
			ops: func(c *lruCache[string, int]) {
				c.Put("a", 1)
				c.Put("b", 2)
				c.Put("c", 3)
				c.Put("a", 9)
				c.Put("d", 4)
			},
			want: []string{"a", "c", "d"},
		},
		{
			name: "removing the head and the tail",
			ops: func(c *lruCache[string, int]) {
				c.Put("a", 1)
				c.Put("b", 2)
				c.Put("c", 3)
				c.Remove("c") // head
				c.Remove("a") // tail
			},
			want: []string{"b"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			capacity := 3
			if tc.name == "capacity below one is raised" {
				capacity = 0
			}
			c := newLRU[string, int](capacity)
			tc.ops(c)
			if got := len(c.m); got != len(tc.want) {
				t.Fatalf("cache length = %d, want %d", got, len(tc.want))
			}
			for _, k := range tc.want {
				if _, ok := c.Get(k); !ok {
					t.Errorf("key %q was evicted, want retained", k)
				}
			}
		})
	}
}

func TestLRUMissAndPurge(t *testing.T) {
	t.Parallel()
	c := newLRU[string, int](4)
	if v, ok := c.Get("nope"); ok || v != 0 {
		t.Errorf("Get(missing) = (%d, %v), want (0, false)", v, ok)
	}
	if c.Remove("nope") {
		t.Error("Remove(missing) = true, want false")
	}
	for i := range 4 {
		c.Put(strconv.Itoa(i), i)
	}
	c.Purge()
	if got := len(c.m); got != 0 {
		t.Errorf("cache length after Purge = %d, want 0", got)
	}
	// The cache must still be usable after a purge.
	c.Put("x", 1)
	if v, ok := c.Get("x"); !ok || v != 1 {
		t.Errorf("Get after Purge = (%d, %v), want (1, true)", v, ok)
	}
}

func TestLRUSingleEntryEvictionPath(t *testing.T) {
	t.Parallel()
	c := newLRU[string, int](1)
	c.Put("a", 1)
	c.Put("b", 2)
	if _, ok := c.Get("a"); ok {
		t.Error("capacity-1 cache retained the evicted entry")
	}
	got := make([]string, 0, 1)
	if _, ok := c.Get("b"); ok {
		got = append(got, "b")
	}
	if diff := cmp.Diff([]string{"b"}, got); diff != "" {
		t.Errorf("retained keys (-want +got):\n%s", diff)
	}
}

func TestLRUIsConcurrencySafe(t *testing.T) {
	t.Parallel()
	c := newLRU[int, int](64)
	var wg sync.WaitGroup
	for g := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 200 {
				k := (g*200 + i) % 128
				c.Put(k, i)
				c.Get(k)
				if i%17 == 0 {
					c.Remove(k)
				}
				if i%97 == 0 {
					c.Purge()
				}
			}
		}()
	}
	wg.Wait()
	if got := len(c.m); got > 64 {
		t.Errorf("cache length = %d, want at most the capacity 64", got)
	}
}
