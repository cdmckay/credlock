package daemon

import (
	"sort"
	"time"

	"github.com/cdmckay/credlock/internal/proto"
)

// key is one secret in one account, approved for one origin: "" for this
// machine, or the tailnet host that asked. The same reference can exist in two
// accounts, and an approval for papaya is not one for this Mac, or the reverse.
type key struct {
	origin, account, ref string
}

type entry struct {
	value    string
	approved time.Time
	expires  time.Time
}

// cache holds approved secrets in the helper's memory, and nowhere else. Every
// delivery slides an entry's expiry out to window from now, but never past cap
// after it was approved, so even a secret in constant use is re-approved daily
// and picks up rotations. Callers hold the server's lock.
type cache struct {
	window, cap time.Duration
	entries     map[key]entry
}

func newCache(window, cap time.Duration) *cache {
	return &cache{window: window, cap: cap, entries: map[key]entry{}}
}

// peek returns a live entry's value without extending it.
func (c *cache) peek(k key, now time.Time) (string, bool) {
	e, ok := c.entries[k]
	if !ok || !now.Before(e.expires) {
		return "", false
	}
	return e.value, true
}

// put records a freshly approved value.
func (c *cache) put(k key, value string, now time.Time) {
	c.entries[k] = entry{value: value, approved: now, expires: c.limit(now, now)}
}

// touch slides a live entry's expiry, because its value was just delivered.
func (c *cache) touch(k key, now time.Time) {
	if e, ok := c.entries[k]; ok && now.Before(e.expires) {
		e.expires = c.limit(e.approved, now)
		c.entries[k] = e
	}
}

func (c *cache) limit(approved, now time.Time) time.Time {
	if slide, hard := now.Add(c.window), approved.Add(c.cap); slide.Before(hard) {
		return slide
	}
	return approved.Add(c.cap)
}

// sweep drops every expired entry, so nothing outlives its expiry by more than
// the sweep interval even if it is never asked for again.
func (c *cache) sweep(now time.Time) {
	for k, e := range c.entries {
		if !now.Before(e.expires) {
			delete(c.entries, k)
		}
	}
}

// forget drops one entry.
func (c *cache) forget(k key) {
	delete(c.entries, k)
}

func (c *cache) clear() {
	c.entries = map[key]entry{}
}

// list describes the live entries, soonest to expire first. No values.
func (c *cache) list(now time.Time) []proto.Entry {
	var out []proto.Entry
	for k, e := range c.entries {
		if now.Before(e.expires) {
			out = append(out, proto.Entry{Origin: k.origin, Account: k.account, Ref: k.ref, ExpiresIn: int64(e.expires.Sub(now).Seconds())})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ExpiresIn != out[j].ExpiresIn {
			return out[i].ExpiresIn < out[j].ExpiresIn
		}
		return out[i].Ref < out[j].Ref
	})
	return out
}
