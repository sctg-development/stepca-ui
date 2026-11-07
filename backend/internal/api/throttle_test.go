package api

import (
	"testing"
	"time"
)

func TestLoginThrottle(t *testing.T) {
	th := newLoginThrottle()
	clock := time.Now()
	th.now = func() time.Time { return clock }

	for i := 0; i < 5; i++ {
		if !th.allow("alice") {
			t.Fatalf("attempt %d must be allowed", i)
		}
		th.fail("alice")
	}
	if th.allow("alice") {
		t.Fatal("alice must be locked after 5 failures")
	}
	if !th.allow("bob") {
		t.Fatal("another account is not affected")
	}
	clock = clock.Add(16 * time.Minute)
	if !th.allow("alice") {
		t.Fatal("the lockout must expire")
	}
	th.fail("alice")
	th.success("alice")
	for i := 0; i < 4; i++ {
		th.fail("alice")
	}
	if !th.allow("alice") {
		t.Fatal("a success resets the counter: 4 new failures stay below the limit")
	}
}

func TestLoginThrottleGlobalRate(t *testing.T) {
	th := newLoginThrottle()
	clock := time.Now()
	th.now = func() time.Time { return clock }
	for i := 0; i < 30; i++ {
		if !th.allow("u" + string(rune('a'+i%26))) {
			t.Fatalf("attempt %d under the global ceiling", i)
		}
	}
	if th.allow("zzz") {
		t.Fatal("the 31st attempt within a minute must be refused")
	}
	clock = clock.Add(61 * time.Second)
	if !th.allow("zzz") {
		t.Fatal("the window slides")
	}
}
