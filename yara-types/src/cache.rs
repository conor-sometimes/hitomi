//! The verdict cache (design `docs/design/yara-sensor.md` section 7.1): a file already scanned
//! under the current rule set is not scanned again, and a cache hit emits nothing (4.2). This is
//! the one thing that makes marking `/nix/store` and `/usr` affordable -- a box runs a few thousand
//! distinct binaries a day, so after warm-up the exec trigger is almost all `fstat` + lookup.
//!
//! Key: `(dev, ino, size, ctime, rulesetHash)`. A rewrite in place changes `ctime` and `size`; a
//! new rule set changes `rulesetHash`; either misses, so a changed file is rescanned. The cache is
//! in memory only (a restart rescans on next exec, a bounded warm-up). Bounded LRU, nothing else.
//!
//! Pure data and a pure container: no syscalls, so the key construction, equality and the LRU
//! eviction order are all unit-tested on the Mac. The daemon fills a [`CacheKey`] from `fstat` +
//! the engine's `ruleset_id`.

use std::collections::BTreeMap;
use std::collections::HashMap;

/// The default cache capacity (entries). A few MB at this size; a box's distinct-binary working set
/// is far smaller, so eviction is rare in steady state. `cacheEntries` in the module.
pub const DEFAULT_CAPACITY: usize = 65_536;

/// The identity of a scanned inode under a rule set. Two scans with the same key are the same
/// verdict; any field differing is a miss and a rescan. `ctime` is the inode change time in
/// `(seconds, nanoseconds)` since the epoch, as `fstat` reports it: a rewrite-in-place bumps it
/// even when size is unchanged, which is the point.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    pub dev: u64,
    pub ino: u64,
    pub size: u64,
    pub ctime_sec: i64,
    pub ctime_nsec: i64,
    /// The rule-set identity the verdict was produced under (`sha256:...`). A rule-set change
    /// changes this and misses every prior entry, which is correct: the verdicts are stale.
    pub ruleset: String,
}

impl CacheKey {
    /// Build a key from the inode facts the daemon has after `fstat`, plus the loaded rule set's
    /// identity. A plain constructor, kept here so the field order is defined in one place.
    pub fn new(
        dev: u64,
        ino: u64,
        size: u64,
        ctime_sec: i64,
        ctime_nsec: i64,
        ruleset: &str,
    ) -> CacheKey {
        CacheKey {
            dev,
            ino,
            size,
            ctime_sec,
            ctime_nsec,
            ruleset: ruleset.to_string(),
        }
    }
}

/// The cached outcome of a scan. A hit carries the matched rule names so a future "re-emit on exec
/// from a different pid" is a flag not a redesign (4.2); `clean`/`failed`/`skipped` carry only what
/// the counters and the start-up report need.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Scanned, nothing matched.
    Clean,
    /// Scanned, these rule identifiers matched (possibly truncated at `maxHitsPerFile`).
    Hits(Vec<String>),
    /// The scan itself failed (e.g. `timeout`, a yara-x scan error): cached so one pathological
    /// file is paid for once, counted, never retried in a loop.
    Failed(String),
    /// Not scanned (e.g. `too large`): cached so the size cap is also paid once per inode.
    Skipped(String),
}

/// A bounded least-recently-used verdict cache. No external LRU crate (the dependency policy keeps
/// the tree minimal): a `HashMap` for the entries and a `BTreeMap` keyed by a monotonic access
/// sequence for O(log n) recency, so `get`, `insert` and eviction are all O(log n) and eviction
/// drops the genuinely least-recently-used entry.
pub struct VerdictCache {
    capacity: usize,
    seq: u64,
    /// key -> (verdict, the access sequence under which it currently sits in `order`).
    entries: HashMap<CacheKey, (Verdict, u64)>,
    /// access sequence -> key, so the smallest sequence is the least-recently-used entry.
    order: BTreeMap<u64, CacheKey>,
}

impl VerdictCache {
    /// A cache holding at most `capacity` entries (clamped to at least 1, so a zero from a
    /// misconfiguration still functions as a 1-entry cache rather than panicking or caching
    /// nothing silently).
    pub fn new(capacity: usize) -> VerdictCache {
        VerdictCache {
            capacity: capacity.max(1),
            seq: 0,
            entries: HashMap::new(),
            order: BTreeMap::new(),
        }
    }

    /// Entries currently held.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when the cache holds nothing.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn next_seq(&mut self) -> u64 {
        self.seq += 1;
        self.seq
    }

    /// Look up a verdict, marking the entry most-recently-used on a hit. Returns a clone of the
    /// verdict (verdicts are small: a few rule names at most).
    pub fn get(&mut self, key: &CacheKey) -> Option<Verdict> {
        let old_seq = match self.entries.get(key) {
            Some((_, seq)) => *seq,
            None => return None,
        };
        let new_seq = self.next_seq();
        // Re-seat this key at the newest sequence.
        self.order.remove(&old_seq);
        self.order.insert(new_seq, key.clone());
        let (verdict, seq) = self.entries.get_mut(key).expect("just found above");
        *seq = new_seq;
        Some(verdict.clone())
    }

    /// Insert or replace a verdict, marking it most-recently-used, evicting the least-recently-used
    /// entry if that pushes the cache over capacity.
    pub fn insert(&mut self, key: CacheKey, verdict: Verdict) {
        let new_seq = self.next_seq();
        if let Some((_, old_seq)) = self.entries.get(&key) {
            self.order.remove(old_seq);
        }
        self.order.insert(new_seq, key.clone());
        self.entries.insert(key, (verdict, new_seq));
        while self.entries.len() > self.capacity {
            // Pop the smallest sequence: the least-recently-used key.
            let lru_seq = *self
                .order
                .keys()
                .next()
                .expect("order is non-empty while entries exceed capacity");
            if let Some(lru_key) = self.order.remove(&lru_seq) {
                self.entries.remove(&lru_key);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(ino: u64, size: u64, ctime_sec: i64, ruleset: &str) -> CacheKey {
        CacheKey::new(8 << 20, ino, size, ctime_sec, 0, ruleset)
    }

    #[test]
    fn rewrite_or_new_ruleset_is_a_miss() {
        let mut c = VerdictCache::new(16);
        let k = key(10, 100, 1000, "sha256:aa");
        c.insert(k.clone(), Verdict::Clean);
        assert_eq!(c.get(&k), Some(Verdict::Clean));
        // same inode, bumped ctime (rewrite in place) -> different key -> miss.
        assert_eq!(c.get(&key(10, 100, 1001, "sha256:aa")), None);
        // same inode+ctime, new rule set -> miss.
        assert_eq!(c.get(&key(10, 100, 1000, "sha256:bb")), None);
    }

    #[test]
    fn stores_hit_rule_names() {
        let mut c = VerdictCache::new(16);
        let k = key(1, 1, 1, "r");
        c.insert(k.clone(), Verdict::Hits(vec!["eicar_test".into()]));
        assert_eq!(c.get(&k), Some(Verdict::Hits(vec!["eicar_test".into()])));
    }

    #[test]
    fn evicts_least_recently_used() {
        let mut c = VerdictCache::new(2);
        let a = key(1, 1, 1, "r");
        let b = key(2, 1, 1, "r");
        let d = key(3, 1, 1, "r");
        c.insert(a.clone(), Verdict::Clean);
        c.insert(b.clone(), Verdict::Clean);
        // touch `a` so `b` becomes least-recently-used.
        assert_eq!(c.get(&a), Some(Verdict::Clean));
        // inserting `d` evicts `b`, not `a`.
        c.insert(d.clone(), Verdict::Clean);
        assert_eq!(c.len(), 2);
        assert_eq!(c.get(&b), None, "b was LRU and should be gone");
        assert_eq!(c.get(&a), Some(Verdict::Clean));
        assert_eq!(c.get(&d), Some(Verdict::Clean));
    }

    #[test]
    fn reinsert_updates_value_without_growing() {
        let mut c = VerdictCache::new(4);
        let k = key(1, 1, 1, "r");
        c.insert(k.clone(), Verdict::Clean);
        c.insert(k.clone(), Verdict::Failed("timeout".into()));
        assert_eq!(c.len(), 1);
        assert_eq!(c.get(&k), Some(Verdict::Failed("timeout".into())));
    }

    #[test]
    fn zero_capacity_behaves_as_one() {
        let mut c = VerdictCache::new(0);
        let a = key(1, 1, 1, "r");
        let b = key(2, 1, 1, "r");
        c.insert(a, Verdict::Clean);
        c.insert(b.clone(), Verdict::Clean);
        assert_eq!(c.len(), 1);
        assert_eq!(c.get(&b), Some(Verdict::Clean));
    }
}
