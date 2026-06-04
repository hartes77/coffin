//! A wild (foreign / dangling / corrupt) pointer dereference.
//!
//! The faulting address belongs to no Coffin allocation, so the handler must
//! report `WILD POINTER` and tear down cleanly — the linear scan finds nothing
//! and must not itself crash or recurse.
//!
//! Expected: a COFFIN report classifying the fault as WILD POINTER, then death
//! by SIGSEGV/SIGBUS.

use std::ptr;

#[global_allocator]
static ALLOC: coffin::Coffin = coffin::Coffin::new();

fn main() {
    // Make sure the handler is armed even though we never allocate on this path.
    coffin::arm();

    let wild = 0x0000_DEAD_0000usize as *mut u8;
    eprintln!("coffin: writing to a wild pointer {wild:p} — expect a WILD POINTER report...");
    unsafe {
        ptr::write_volatile(wild, 0x42);
    }
    eprintln!("coffin: ERROR — wild write was not caught (this should be unreachable)");
}
