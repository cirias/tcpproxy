package transport

import (
	"testing"
)

func TestKeyGenerator(t *testing.T) {
	g := NewKeyGenerator()

	{
		i := 0
		key := g.Next()
		if key != i {
			t.Fatalf("key should be %d, but not %d", i, key)
		}

		g.Recycle(key)
	}

	for i := 0; i < 1000; i++ {
		key := g.Next()
		if key != i {
			t.Fatalf("key should be %d, but not %d", i, key)
		}
	}

	{
		i := 100
		g.Recycle(i)
		key := g.Next()
		if key != i {
			t.Fatalf("key should be %d, but not %d", i, key)
		}
	}

	{
		i := 1000
		key := g.Next()
		if key != i {
			t.Fatalf("key should be %d, but not %d", i, key)
		}
	}

	for _, i := range []int{444, 333, 222, 111} {
		g.Recycle(i)
	}

	for _, i := range []int{111, 222, 333, 444} {
		key := g.Next()
		if key != i {
			t.Fatalf("key should be %d, but not %d", i, key)
		}
	}

	{
		i := 1001
		key := g.Next()
		if key != i {
			t.Fatalf("key should be %d, but not %d", i, key)
		}
	}
}
