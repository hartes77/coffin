//! # Coffin
//!
//! A page-fencing `#[global_allocator]` for hunting memory corruption in
//! canary / CI / staging builds. Spiritual heir to Electric Fence, but
//! production-grade, lock-free for reads, and portable from day one
//! (Linux x86_64 + macOS aarch64).
//!
//! ## Principle
//!
//! Every allocation lives on its own dedicated pages with an adjacent
//! `PROT_NONE` **guard page**. An overflow (or, in `below` mode, an underflow)
//! steps onto the guard page and faults *immediately, at the exact byte*. On
//! free the whole region is made `PROT_NONE` and its address is **not reused**
//! until it ages out of quarantine, so use-after-free also faults at the exact
//! address.
//!
//! ## Usage
//!
//! ```no_run
//! #[global_allocator]
//! static A: coffin::Coffin = coffin::Coffin::new();
//! ```
//!
//! ## Tuning (environment)
//!
//! | Var                     | Meaning                                       | Default   |
//! |-------------------------|-----------------------------------------------|-----------|
//! | `COFFIN_PROTECT`        | `above` (overflow) / `below` (underflow)      | `above`   |
//! | `COFFIN_MAX_LIVE`       | registry slots (→ next power of two)          | `1048576` |
//! | `COFFIN_QUARANTINE`     | freed regions kept dead before recycling      | `4096`    |
//! | `COFFIN_SYMBOLIZE`      | `1` to demangle/resolve the captured stacks   | off       |
//! | `COFFIN_ON_FAULT`       | `abort` / `exit:<N>` termination policy       | `abort`   |
//! | `COFFIN_GITHUB_ANNOTATE`| `1` to emit GitHub Actions `::error` lines    | off       |
//!
//! ## Cost
//!
//! At least one page per allocation (16 KiB on Apple Silicon). This is a
//! debugging tool for canary/CI, **not** an always-on production hot-path
//! allocator.

mod config;
mod handler;
mod region;
mod registry;
mod report;

pub use config::{max_live_slots, mode, page_size, quarantine_cap, Mode};

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

thread_local! {
    /// Reentrancy guard (iron rule #6). Coffin's own bookkeeping must never
    /// recurse into Coffin: while this is set, nested (de)allocations are routed
    /// straight to the system allocator. `const`-initialized ⇒ no heap on first
    /// touch of the thread-local.
    static IN_COFFIN: Cell<bool> = const { Cell::new(false) };
}

/// Enter the Coffin critical section. Returns false if we are already inside
/// (reentrant) or the thread-local is gone (thread teardown) — in both cases
/// the caller must delegate to `System`.
#[inline]
fn enter() -> bool {
    IN_COFFIN
        .try_with(|c| {
            if c.get() {
                false
            } else {
                c.set(true);
                true
            }
        })
        .unwrap_or(false)
}

#[inline]
fn leave() {
    let _ = IN_COFFIN.try_with(|c| c.set(false));
}

/// Force the reentrancy guard on, irreversibly for this thread. Used only by
/// the signal handler before opt-in symbolization, so any allocation it makes
/// is served by `System` instead of re-entering Coffin (and its spinlock).
#[inline]
pub(crate) fn force_guard() {
    let _ = IN_COFFIN.try_with(|c| c.set(true));
}

/// Eagerly initialize the registry and (re)arm the SIGSEGV/SIGBUS handler.
///
/// **Recommended as the first line of `main`.** Coffin arms itself on the first
/// allocation, but the std runtime installs its *own* SIGSEGV handler (the
/// stack-overflow guard) during startup. If Coffin's first allocation happens
/// before that — which it does on Linux — std's handler is installed last and
/// shadows Coffin's, so overflow/use-after-free faults (delivered as SIGSEGV on
/// Linux) would die uncaught. `arm()` re-asserts Coffin's disposition after std,
/// guaranteeing it wins on every platform. Idempotent and always safe to call.
pub fn arm() {
    registry::registry();
    handler::install();
}

/// The page-fencing global allocator. Stateless: all state lives in
/// process-wide statics, so it is trivially `const`-constructible.
pub struct Coffin;

impl Coffin {
    pub const fn new() -> Self {
        Coffin
    }
}

impl Default for Coffin {
    fn default() -> Self {
        Coffin::new()
    }
}

// SAFETY: `alloc` returns either null or a pointer to `layout.size()` writable
// bytes aligned to `layout.align()`. `dealloc` seals/recycles exactly the region
// produced for that pointer, or forwards to `System` for non-Coffin pointers.
unsafe impl GlobalAlloc for Coffin {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if !enter() {
            return System.alloc(layout);
        }
        let p = coffin_alloc(layout);
        leave();
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ptr.is_null() {
            return;
        }
        if !enter() {
            // Reentrant frees can only be of System-allocated internals.
            System.dealloc(ptr, layout);
            return;
        }
        coffin_dealloc(ptr, layout);
        leave();
    }
}

/// Fenced allocation + registry insert. Falls back to `System` (unfenced) when
/// the registry is full. Must be called inside the reentrancy guard.
#[inline]
unsafe fn coffin_alloc(layout: Layout) -> *mut u8 {
    let geom = region::region_geometry(layout);
    let (base, user) = region::map_region(layout, &geom);
    if user.is_null() {
        return std::ptr::null_mut(); // mmap failed → runtime calls handle_alloc_error
    }

    let arena = registry::registry();
    let guard_addr = base as usize + geom.guard_off;
    let inserted = arena.insert(
        base as usize,
        geom.map_len,
        user as usize,
        layout.size().max(1),
        layout.align(),
        guard_addr,
    );

    if inserted {
        user
    } else {
        // Registry full: give the fenced VA back and serve from System unfenced.
        region::unmap(base, geom.map_len);
        arena.warn_full_once();
        System.alloc(layout)
    }
}

/// Free path. Looks the pointer up in the registry: a hit is a fenced Coffin
/// allocation (sealed PROT_NONE + quarantined); a miss is a System-fallback
/// pointer (forwarded to System). Must be called inside the reentrancy guard.
#[inline]
unsafe fn coffin_dealloc(ptr: *mut u8, layout: Layout) {
    // Catch overflow into alignment padding before sealing (pathological case).
    region::check_padding(ptr, layout);

    let geom = region::region_geometry(layout);
    let arena = registry::registry();
    match arena.free(ptr as usize, geom.map_len) {
        Some(true) => {} // fenced + quarantined
        Some(false) => report::raw_write(&[b"coffin: double free detected\n"]),
        None => System.dealloc(ptr, layout), // was a System-fallback allocation
    }
}

// ───────────────────────────── inspection API ─────────────────────────────
// Lock-free reads of the registry, for tests and examples.

/// Slot state for `ptr`: `"ready"`, `"freed"`, or `None` if untracked.
pub fn slot_state(ptr: *const u8) -> Option<&'static str> {
    match registry::registry().state_of(ptr as usize)? {
        registry::READY => Some("ready"),
        registry::FREED => Some("freed"),
        _ => None,
    }
}

/// Number of currently live (allocated, not yet freed) fenced allocations.
pub fn live_count() -> usize {
    registry::registry().live_count()
}

/// Number of regions evicted from quarantine and `munmap`'d so far.
pub fn eviction_count() -> usize {
    registry::registry().eviction_count()
}

/// Current number of regions sitting in quarantine.
pub fn quarantine_len() -> usize {
    registry::registry().quarantine_len()
}
