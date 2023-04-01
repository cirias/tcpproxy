package transport

import (
	"fmt"
	"sync"
)

type KeyGenerator struct {
	mutex   sync.Mutex
	entries []Entry
	next    int
}

type Entry struct {
	// next is valid only when not occupied
	next  int
	value interface{}
}

func NewKeyGenerator() *KeyGenerator {
	return &KeyGenerator{
		entries: make([]Entry, 0, 128),
		next:    0,
	}
}

func (g *KeyGenerator) Next() int {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	key := g.next

	// full
	if g.next == len(g.entries) {
		g.entries = append(g.entries, Entry{next: -1})
		g.next += 1
		return key
	}

	g.next = g.entries[key].next
	g.entries[key].next = -1
	return key
}

func (g *KeyGenerator) Recycle(key int) {
	size := len(g.entries)
	if key < 0 || key >= size {
		panic(fmt.Sprintf("trying to recycle an invalid key %d vs size %d", key, size))
	}

	g.mutex.Lock()
	defer g.mutex.Unlock()

	g.entries[key] = Entry{next: g.next}
	g.next = key
}
