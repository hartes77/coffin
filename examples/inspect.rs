//! Non-crashing verification of the Phase 2 mechanics:
//!
//!  1. after free the slot is `freed` in the registry,
//!  2. the freed page really is `PROT_NONE` (proven by touching it in a *child*
//!     process, so this parent survives to report the result),
//!  3. quarantine is a bounded ring: once full, freeing more `munmap`s the
//!     oldest region (eviction counter rises, quarantine length stays capped) —
//!     i.e. no unbounded VMA growth.

use std::alloc::{alloc, dealloc, Layout};
use std::io::Write;
use std::ptr;

#[global_allocator]
static ALLOC: coffin::Coffin = coffin::Coffin::new();

fn main() {
    // ── 1 & 2: Freed state + PROT_NONE ──────────────────────────────────────
    let layout = Layout::from_size_align(128, 16).unwrap();
    let p = unsafe { alloc(layout) };
    assert!(!p.is_null());
    unsafe { ptr::write_bytes(p, 0xAA, 128) };

    println!("[1] allocated {p:p}");
    println!("    state      = {:?}", coffin::slot_state(p));
    println!("    live_count = {}", coffin::live_count());
    assert_eq!(coffin::slot_state(p), Some("ready"));

    unsafe { dealloc(p, layout) };
    println!("[2] freed {p:p}");
    println!("    state      = {:?}", coffin::slot_state(p));
    assert_eq!(coffin::slot_state(p), Some("freed"));

    // Touch the freed page in a child so a fault doesn't kill us.
    std::io::stdout().flush().ok();
    println!("[3] forking a child to touch the freed page...");
    std::io::stdout().flush().ok();
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        // Child: this write must fault on the PROT_NONE page.
        unsafe { ptr::write_volatile(p, 0x00) };
        unsafe { libc::_exit(0) }; // only reached if the seal FAILED
    }
    let mut status: libc::c_int = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    if libc::WIFSIGNALED(status) {
        let sig = libc::WTERMSIG(status);
        println!("    child killed by signal {sig} -> freed page is PROT_NONE [ok]");
    } else {
        println!("    child exited normally -> PROT_NONE seal FAILED [fail]");
        std::process::exit(1);
    }

    // ── 3: bounded quarantine with eviction ─────────────────────────────────
    let qcap = coffin::quarantine_cap();
    println!("[4] quarantine cap = {qcap}");
    let small = Layout::from_size_align(32, 8).unwrap();
    let rounds = qcap + 100;
    let evictions_before = coffin::eviction_count();

    for _ in 0..rounds {
        unsafe {
            let q = alloc(small);
            assert!(!q.is_null());
            dealloc(q, small);
        }
    }

    let evicted = coffin::eviction_count() - evictions_before;
    println!("    freed {rounds} regions");
    println!("    quarantine_len = {} (must stay <= {qcap})", coffin::quarantine_len());
    println!("    evictions (oldest munmap'd) = {evicted}");
    assert!(evicted > 0, "expected evictions once quarantine filled");
    assert!(evicted >= rounds - qcap, "every free past the cap should evict one");
    assert!(coffin::quarantine_len() <= qcap, "quarantine must stay bounded");
    println!("    -> VA reclaimed past the window; no unbounded VMA growth [ok]");

    println!("inspect: all checks passed");
}
