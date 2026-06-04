//! Use-after-free under Coffin.
//!
//! After `dealloc`, the region is sealed `PROT_NONE` and parked in quarantine —
//! its address is NOT handed back out. So touching the freed pointer faults
//! immediately and deterministically at the exact address.
//!
//! Expected result: terminated by SIGSEGV (or SIGBUS on macOS). It must NOT
//! print the "unreachable" line.

use std::alloc::{alloc, dealloc, Layout};
use std::ptr;

#[global_allocator]
static ALLOC: coffin::Coffin = coffin::Coffin::new();

fn main() {
    let layout = Layout::from_size_align(64, 8).unwrap();

    unsafe {
        let p = alloc(layout);
        assert!(!p.is_null());
        ptr::write_volatile(p, 1); // live: this is fine
        eprintln!(
            "coffin: allocated {p:p}, state = {:?}",
            coffin::slot_state(p)
        );

        dealloc(p, layout);
        eprintln!("coffin: freed {p:p}, state = {:?}", coffin::slot_state(p));

        eprintln!("coffin: touching the freed pointer — expect an immediate SIGSEGV/SIGBUS...");
        ptr::write_volatile(p, 2); // use-after-free → fault

        eprintln!("coffin: ERROR — use-after-free was not caught (this should be unreachable)");
    }
}
