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
	value   string
	expires time.Time
	// until is when the approval ends however often it is used: cap after it
	// was approved, or sooner if a request asked for less (credlock run --ttl).
	until time.Time
}

// cache holds approved secrets in the helper's memory, and nowhere else. Every
// delivery slides an entry's expiry out to window from now, but never past cap
// after it was approved, so even a secret in constant use is re-approved daily
// and picks up rotations. A request's TTL brings that end closer, never
// further. Callers hold the server's lock.
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

// put records a freshly approved value, which lasts at most ttl from now if
// ttl is positive.
func (c *cache) put(k key, value string, now time.Time, ttl time.Duration) {
	until := shorten(now.Add(c.cap), now, ttl)
	c.entries[k] = entry{value: value, until: until, expires: c.limit(until, now)}
}

// touch slides a live entry's expiry, because its value was just delivered,
// for a request that wants it to last at most ttl from now if ttl is positive.
func (c *cache) touch(k key, now time.Time, ttl time.Duration) {
	if e, ok := c.entries[k]; ok && now.Before(e.expires) {
		e.until = shorten(e.until, now, ttl)
		e.expires = c.limit(e.until, now)
		c.entries[k] = e
	}
}

func (c *cache) limit(until, now time.Time) time.Time {
	if slide := now.Add(c.window); slide.Before(until) {
		return slide
	}
	return until
}

// shorten brings until in to ttl from now, if ttl is positive and that's
// sooner. It never moves until later.
func shorten(until, now time.Time, ttl time.Duration) time.Time {
	if end := now.Add(ttl); ttl > 0 && end.Before(until) {
		return end
	}
	return until
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

// forgetRefs drops origin's entries for refs, in account, or in every account
// if account is empty. It describes the live ones it dropped, without values.
func (c *cache) forgetRefs(origin, account string, refs []string, now time.Time) []proto.Entry {
	wanted := map[string]bool{}
	for _, ref := range refs {
		wanted[ref] = true
	}
	var gone []proto.Entry
	for k, e := range c.entries {
		if k.origin != origin || !wanted[k.ref] || (account != "" && k.account != account) {
			continue
		}
		delete(c.entries, k)
		if now.Before(e.expires) {
			gone = append(gone, proto.Entry{Origin: k.origin, Account: k.account, Ref: k.ref})
		}
	}
	sort.Slice(gone, func(i, j int) bool {
		if gone[i].Ref != gone[j].Ref {
			return gone[i].Ref < gone[j].Ref
		}
		return gone[i].Account < gone[j].Account
	})
	return gone
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
