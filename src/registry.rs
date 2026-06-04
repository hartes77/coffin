//! The allocation registry: a fixed-slot, lock-free-for-readers arena that
//! tracks every live and quarantined Coffin allocation.
//!
//! ## Why this shape (iron rule #4)
//!
//! * **Fixed slots, pre-mmap'd.** No `HashMap`, no `Mutex`-guarded growth. The
//!   arena is one `mmap` of `COFFIN_MAX_LIVE` `Region`s at first use. It is
//!   demand-zero: only touched slots ever cost physical RAM, and `Empty == 0`
//!   means the zero-filled mapping is already a valid empty table.
//!
//! * **Publish-last with `Release`.** A writer fills all fields with relaxed
//!   stores, then stores `state = Ready` with `Ordering::Release`. A reader
//!   loads `state` with `Acquire` and skips anything not `Ready`/`Freed`, so it
//!   never observes a torn entry. Fields are atomics so the lock-free reader
//!   (the Phase 3 SIGSEGV handler) never has a data race.
//!
//! * **Writers take a light spinlock; readers take nothing.** Insert / free /
//!   evict are serialized by one [`SpinLock`]; the handler reads with no lock.
//!
//! ## Lookup strategy
//!
//! Hot-path `dealloc` needs to find a slot by exact `user_ptr` fast, so the
//! table is open-addressed (Fibonacci-hashed, linear probing). `Tomb` markers
//! left by quarantine eviction keep probe chains intact and are recycled by
//! later inserts, so a long-running process does not degrade. The Phase 3
//! handler instead does a blessed O(n) linear scan by address *range* — it runs
//! while the process is already dying, so latency is irrelevant and robustness
//! is everything.

use crate::config::{max_live_slots, quarantine_cap};
use crate::region;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::OnceLock;

/// Depth of the alloc/free backtrace captured per slot. Fields exist now;
/// populated in Phase 3.
pub const IP_DEPTH: usize = 16;

// Slot lifecycle states (stored in `Region::state`). `Empty == 0` so a
// freshly-mmap'd (zeroed) arena starts entirely empty with no init pass.
pub const EMPTY: u8 = 0;
pub const READY: u8 = 1;
pub const FREED: u8 = 2;
pub const TOMB: u8 = 3;

/// One tracked allocation. All reader-visible fields are atomics so the
/// lock-free SIGSEGV handler can read them without UB; writers only mutate them
/// while holding the arena spinlock.
#[repr(C)]
pub struct Region {
    pub state: AtomicU8Cell,
    pub base: AtomicUsize,
    pub total_len: AtomicUsize,
    pub user_ptr: AtomicUsize,
    pub size: AtomicUsize,
    pub align: AtomicUsize,
    /// Start address of the guard page (lets the handler classify overflow).
    pub guard_addr: AtomicUsize,
    /// Raw instruction pointers of the alloc / free call sites (Phase 3).
    pub alloc_ips: [AtomicUsize; IP_DEPTH],
    pub free_ips: [AtomicUsize; IP_DEPTH],
}

// `AtomicU8` re-export under a local name purely so the `#[repr(C)]` struct
// literal stays readable.
pub use std::sync::atomic::AtomicU8 as AtomicU8Cell;

/// A minimal spinlock (no poisoning, no allocation) serializing writers.
pub struct SpinLock {
    held: AtomicBool,
}

impl SpinLock {
    const fn new() -> Self {
        SpinLock {
            held: AtomicBool::new(false),
        }
    }

    #[inline]
    fn lock(&self) -> SpinGuard<'_> {
        while self
            .held
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            std::hint::spin_loop();
        }
        SpinGuard { lock: self }
    }
}

pub struct SpinGuard<'a> {
    lock: &'a SpinLock,
}

impl Drop for SpinGuard<'_> {
    #[inline]
    fn drop(&mut self) {
        self.lock.held.store(false, Ordering::Release);
    }
}

/// The fixed-slot arena plus the quarantine ring. Raw pointers are set once at
/// construction and then immutable; the ring cursors are mutated only under
/// `lock`.
pub struct Arena {
    slots: *mut Region,
    cap: usize,  // power of two
    mask: usize, // cap - 1
    ring: *mut usize,
    q_cap: usize,
    lock: SpinLock,
    // Ring cursors. Touched only under `lock`; atomic only so the struct is Sync.
    q_tail: AtomicUsize,
    q_len: AtomicUsize,
    // Observability counters.
    live: AtomicUsize,
    evictions: AtomicUsize,
    full_warned: AtomicBool,
}

// SAFETY: the raw pointers address process-lifetime mmap'd memory; all mutation
// is serialized by `lock` (or is to atomics), and readers only do atomic loads.
unsafe impl Send for Arena {}
unsafe impl Sync for Arena {}

static REGISTRY: OnceLock<Arena> = OnceLock::new();

/// Get (initializing on first call) the process-wide registry. The init closure
/// only `mmap`s and reads env — it never allocates, so it is safe to run from
/// inside the global allocator.
#[inline]
pub fn registry() -> &'static Arena {
    REGISTRY.get_or_init(Arena::new)
}

#[inline]
fn hash(ptr: usize) -> usize {
    // Fibonacci hashing: mixes the (page-correlated) low bits up.
    ptr.wrapping_mul(0x9E37_79B9_7F4A_7C15)
}

/// Capture the current call stack's raw instruction pointers into `out`,
/// zero-padding the tail. Uses `trace_unsynchronized`, which only *walks* the
/// stack (no symbolization, no heap, no lock) — safe to call while holding the
/// writer lock. Excess frames beyond `IP_DEPTH` are dropped.
#[inline]
fn capture_ips(out: &[AtomicUsize; IP_DEPTH]) {
    let mut i = 0usize;
    // SAFETY: trace_unsynchronized does not allocate and we run inside the
    // reentrancy guard regardless; the closure only stores integers.
    unsafe {
        backtrace::trace_unsynchronized(|frame| {
            if i < IP_DEPTH {
                out[i].store(frame.ip() as usize, Ordering::Relaxed);
                i += 1;
                true
            } else {
                false
            }
        });
    }
    while i < IP_DEPTH {
        out[i].store(0, Ordering::Relaxed);
        i += 1;
    }
}

/// How a faulting address relates to the tracked allocations.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FaultKind {
    /// Wrote past the end of a live buffer (guard page after it).
    Overflow,
    /// Wrote before the start of a live buffer (guard page before it).
    Underflow,
    /// Touched a freed buffer still sealed in quarantine.
    UseAfterFree,
    /// Inside a live region but not the guard page — should not normally fault.
    LiveRegion,
    /// No tracked region contains the address: dangling/foreign/corrupt pointer.
    Wild,
}

/// Result of classifying a faulting address (filled by the lock-free scan).
pub struct FaultInfo {
    pub kind: FaultKind,
    pub slot: usize, // usize::MAX when Wild
    pub base: usize,
    pub total_len: usize,
    pub user_ptr: usize,
    pub size: usize,
    pub align: usize,
}

/// Get the process registry WITHOUT initializing it. The signal handler uses
/// this — it must never trigger arena setup from inside a fault.
#[inline]
pub fn try_get() -> Option<&'static Arena> {
    REGISTRY.get()
}

impl Arena {
    fn new() -> Arena {
        let cap = max_live_slots();
        let q_cap = quarantine_cap();

        let slots_bytes = cap
            .checked_mul(core::mem::size_of::<Region>())
            .expect("COFFIN_MAX_LIVE too large");
        // SAFETY: fresh mmap; demand-zero gives every Region state == EMPTY.
        let slots = unsafe { region::map_raw(slots_bytes) } as *mut Region;
        let ring = unsafe { region::map_raw(q_cap * core::mem::size_of::<usize>()) } as *mut usize;
        if slots.is_null() || ring.is_null() {
            // Catastrophic: we cannot even map our own metadata. Crash loudly
            // rather than limp on with a half-built registry.
            crate::report::raw_write(&[b"coffin: FATAL: failed to mmap registry arena\n"]);
            std::process::abort();
        }

        // Arm the SIGSEGV/SIGBUS handler now, on the very first allocation, so a
        // fault on any fenced page produces a report. Idempotent.
        crate::handler::install();

        Arena {
            slots,
            cap,
            mask: cap - 1,
            ring,
            q_cap,
            lock: SpinLock::new(),
            q_tail: AtomicUsize::new(0),
            q_len: AtomicUsize::new(0),
            live: AtomicUsize::new(0),
            evictions: AtomicUsize::new(0),
            full_warned: AtomicBool::new(false),
        }
    }

    #[inline]
    unsafe fn slot(&self, idx: usize) -> &Region {
        &*self.slots.add(idx)
    }

    // ───────────────────────────── writer side ─────────────────────────────

    /// Record a freshly fenced allocation. Returns false if the table is full
    /// (caller falls back to the System allocator).
    pub unsafe fn insert(
        &self,
        base: usize,
        total_len: usize,
        user_ptr: usize,
        size: usize,
        align: usize,
        guard_addr: usize,
    ) -> bool {
        let _g = self.lock.lock();
        let mut idx = hash(user_ptr) & self.mask;
        for _ in 0..self.cap {
            let slot = self.slot(idx);
            let st = slot.state.load(Ordering::Relaxed);
            if st == EMPTY || st == TOMB {
                // Fill every field first...
                slot.base.store(base, Ordering::Relaxed);
                slot.total_len.store(total_len, Ordering::Relaxed);
                slot.user_ptr.store(user_ptr, Ordering::Relaxed);
                slot.size.store(size, Ordering::Relaxed);
                slot.align.store(align, Ordering::Relaxed);
                slot.guard_addr.store(guard_addr, Ordering::Relaxed);
                capture_ips(&slot.alloc_ips);
                // ...then publish with Release so readers see a complete entry.
                slot.state.store(READY, Ordering::Release);
                self.live.fetch_add(1, Ordering::Relaxed);
                return true;
            }
            idx = (idx + 1) & self.mask;
        }
        false
    }

    /// Locked lookup by exact user pointer (hot path). Returns the slot index.
    unsafe fn find_locked(&self, user_ptr: usize) -> Option<usize> {
        let mut idx = hash(user_ptr) & self.mask;
        for _ in 0..self.cap {
            let slot = self.slot(idx);
            match slot.state.load(Ordering::Relaxed) {
                EMPTY => return None, // end of probe chain
                TOMB => {}            // skip, keep probing
                _ => {
                    if slot.user_ptr.load(Ordering::Relaxed) == user_ptr {
                        return Some(idx);
                    }
                }
            }
            idx = (idx + 1) & self.mask;
        }
        None
    }

    /// Free a Coffin allocation: mark the slot `Freed`, seal the whole region
    /// `PROT_NONE`, and push it into quarantine (evicting+unmapping the oldest
    /// if the ring is full). Returns:
    ///   * `Some(true)`  — freed successfully,
    ///   * `Some(false)` — double free detected (slot already `Freed`),
    ///   * `None`        — pointer is not a Coffin allocation (System fallback).
    pub unsafe fn free(&self, user_ptr: usize, total_len: usize) -> Option<bool> {
        let _g = self.lock.lock();
        let idx = self.find_locked(user_ptr)?;
        let slot = self.slot(idx);

        if slot.state.load(Ordering::Relaxed) == FREED {
            return Some(false); // double free
        }

        let base = slot.base.load(Ordering::Relaxed);
        capture_ips(&slot.free_ips);
        // Seal buffer AND guard: any later touch (use-after-free) faults.
        region::protect_none(base as *mut u8, total_len);
        slot.state.store(FREED, Ordering::Release);
        self.live.fetch_sub(1, Ordering::Relaxed);

        self.quarantine_push(idx);
        Some(true)
    }

    /// Push slot `idx` onto the quarantine ring. When full, evict the oldest:
    /// `munmap` it (returning its VA so we never blow past `vm.max_map_count`)
    /// and tombstone its slot. Trade-off: a use-after-free is caught only while
    /// the region stays in this window of `COFFIN_QUARANTINE` freed allocations.
    unsafe fn quarantine_push(&self, idx: usize) {
        let tail = self.q_tail.load(Ordering::Relaxed);
        let len = self.q_len.load(Ordering::Relaxed);

        if len == self.q_cap {
            // Ring full → evict oldest (at tail).
            let victim = *self.ring.add(tail);
            self.evict(victim);
            *self.ring.add(tail) = idx;
            self.q_tail.store((tail + 1) % self.q_cap, Ordering::Relaxed);
            // q_len stays == q_cap
        } else {
            let pos = (tail + len) % self.q_cap;
            *self.ring.add(pos) = idx;
            self.q_len.store(len + 1, Ordering::Relaxed);
        }
    }

    /// Definitively reclaim a quarantined region: unmap its pages and tombstone
    /// the slot (keeps probe chains intact; reused by future inserts).
    unsafe fn evict(&self, idx: usize) {
        let slot = self.slot(idx);
        let base = slot.base.load(Ordering::Relaxed);
        let len = slot.total_len.load(Ordering::Relaxed);
        region::unmap(base as *mut u8, len);
        slot.state.store(TOMB, Ordering::Release);
        self.evictions.fetch_add(1, Ordering::Relaxed);
    }

    /// Emit the arena-full warning exactly once.
    pub fn warn_full_once(&self) {
        if self
            .full_warned
            .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            crate::report::raw_write(&[
                b"coffin: registry full (COFFIN_MAX_LIVE reached) \xe2\x80\x94 ",
                b"falling back to the system allocator (these allocations are NOT fenced)\n",
            ]);
        }
    }

    // ───────────────────────────── reader side ─────────────────────────────

    /// Lock-free lookup of a slot's state by exact user pointer. Reads `state`
    /// with `Acquire` (pairs with the writer's `Release`). Used by tests and,
    /// in Phase 3, conceptually by the handler. Returns the published state.
    pub fn state_of(&self, user_ptr: usize) -> Option<u8> {
        let mut idx = hash(user_ptr) & self.mask;
        for _ in 0..self.cap {
            // SAFETY: idx is always in-bounds (masked).
            let slot = unsafe { self.slot(idx) };
            let st = slot.state.load(Ordering::Acquire);
            match st {
                EMPTY => return None,
                TOMB => {}
                _ => {
                    if slot.user_ptr.load(Ordering::Relaxed) == user_ptr {
                        return Some(st);
                    }
                }
            }
            idx = (idx + 1) & self.mask;
        }
        None
    }

    /// Blessed O(n) linear scan (iron rule #5): find the region containing
    /// `addr` and classify the fault. Lock-free — every field is read with
    /// `Acquire` on `state` then relaxed loads. Non-Ready/Freed slots are
    /// skipped. Runs while the process is already dying, so latency is moot and
    /// robustness is everything; a torn read at worst misclassifies as Wild.
    pub fn classify(&self, addr: usize) -> FaultInfo {
        let page = crate::page_size();
        for idx in 0..self.cap {
            // SAFETY: idx masked into range.
            let slot = unsafe { self.slot(idx) };
            let st = slot.state.load(Ordering::Acquire);
            if st != READY && st != FREED {
                continue;
            }
            let base = slot.base.load(Ordering::Relaxed);
            let total = slot.total_len.load(Ordering::Relaxed);
            if addr >= base && addr < base + total {
                let user = slot.user_ptr.load(Ordering::Relaxed);
                let guard = slot.guard_addr.load(Ordering::Relaxed);
                let kind = if st == FREED {
                    FaultKind::UseAfterFree
                } else if addr >= guard && addr < guard + page {
                    // Guard sits after the buffer ⇒ overflow; before ⇒ underflow.
                    if guard >= user {
                        FaultKind::Overflow
                    } else {
                        FaultKind::Underflow
                    }
                } else {
                    FaultKind::LiveRegion
                };
                return FaultInfo {
                    kind,
                    slot: idx,
                    base,
                    total_len: total,
                    user_ptr: user,
                    size: slot.size.load(Ordering::Relaxed),
                    align: slot.align.load(Ordering::Relaxed),
                };
            }
        }
        FaultInfo {
            kind: FaultKind::Wild,
            slot: usize::MAX,
            base: 0,
            total_len: 0,
            user_ptr: 0,
            size: 0,
            align: 0,
        }
    }

    /// Copy a slot's captured instruction pointers onto the stack (no heap).
    /// `free = true` returns the free-site stack, else the alloc-site stack.
    pub fn read_ips(&self, idx: usize, free: bool) -> [usize; IP_DEPTH] {
        let mut out = [0usize; IP_DEPTH];
        if idx >= self.cap {
            return out;
        }
        // SAFETY: idx bounds-checked above.
        let slot = unsafe { self.slot(idx) };
        let arr = if free { &slot.free_ips } else { &slot.alloc_ips };
        for (o, a) in out.iter_mut().zip(arr.iter()) {
            *o = a.load(Ordering::Relaxed);
        }
        out
    }

    #[inline]
    pub fn live_count(&self) -> usize {
        self.live.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn eviction_count(&self) -> usize {
        self.evictions.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn quarantine_len(&self) -> usize {
        self.q_len.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    impl Arena {
        /// Build a standalone arena (not the process global) with an explicit,
        /// small capacity. Lets us exercise the pure table logic — insert,
        /// probe, lookup, full — without touching real memory via free/evict.
        fn for_test(cap: usize, q_cap: usize) -> Arena {
            assert!(cap.is_power_of_two());
            let slots =
                unsafe { region::map_raw(cap * core::mem::size_of::<Region>()) } as *mut Region;
            let ring = unsafe { region::map_raw(q_cap * core::mem::size_of::<usize>()) } as *mut usize;
            assert!(!slots.is_null() && !ring.is_null());
            Arena {
                slots,
                cap,
                mask: cap - 1,
                ring,
                q_cap,
                lock: SpinLock::new(),
                q_tail: AtomicUsize::new(0),
                q_len: AtomicUsize::new(0),
                live: AtomicUsize::new(0),
                evictions: AtomicUsize::new(0),
                full_warned: AtomicBool::new(false),
            }
        }

        /// Insert a slot identified only by `user_ptr` (other fields irrelevant
        /// for table-structure tests, which never call free/evict).
        unsafe fn insert_key(&self, user_ptr: usize) -> bool {
            self.insert(0, 0, user_ptr, 0, 0, 0)
        }
    }

    #[test]
    fn insert_lookup_roundtrip() {
        let a = Arena::for_test(16, 4);
        let keys = [0x1_0000usize, 0x2_0000, 0x3_0000, 0xDEAD_0000];
        for &k in &keys {
            assert!(unsafe { a.insert_key(k) });
        }
        assert_eq!(a.live_count(), keys.len());
        for &k in &keys {
            assert_eq!(a.state_of(k), Some(READY), "key {k:#x} should be Ready");
        }
        assert_eq!(a.state_of(0xBEEF_0000), None, "unknown key must miss");
    }

    #[test]
    fn collisions_probe_then_fill() {
        // Distinct keys collide into the same bucket (low bits ignored by the
        // hash); linear probing must still place and find them all.
        let a = Arena::for_test(16, 4);
        for i in 0..16usize {
            assert!(unsafe { a.insert_key(0xA000 + i) }, "insert {i} should fit");
        }
        // Table is now full (16/16) -> the next insert fails (caller falls back).
        assert!(!unsafe { a.insert_key(0xFFFF) }, "full table must reject insert");
        for i in 0..16usize {
            assert_eq!(a.state_of(0xA000 + i), Some(READY));
        }
    }
}
