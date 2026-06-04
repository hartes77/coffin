//! A one-byte buffer overflow under Coffin.
//!
//! In `above` mode the end of the buffer abuts the guard page, so writing one
//! byte past the end steps directly onto `PROT_NONE` memory and the process
//! dies *immediately* — deterministically, at the exact faulting byte.
//!
//! Expected result: terminated by SIGSEGV (or SIGBUS on macOS). It must NOT
//! print the "should be unreachable" line.

use std::ptr;

#[global_allocator]
static ALLOC: coffin::Coffin = coffin::Coffin::new();

fn main() {
    // Re-assert Coffin's handler after std's startup (see `arm` docs).
    coffin::arm();

    const N: usize = 64;

    // A Vec<u8> of exactly N bytes (align 1, size N ⇒ size % align == 0 ⇒
    // byte-exact fence, zero padding). Its last byte sits flush against the
    // guard page.
    let mut buf: Vec<u8> = vec![0u8; N];
    let p = buf.as_mut_ptr();

    eprintln!(
        "coffin: allocated {N} bytes at {:p}; the byte at offset {N} is the guard page",
        p
    );
    eprintln!("coffin: writing 1 byte past the end — expect an immediate SIGSEGV/SIGBUS...");

    // SAFETY: deliberately out of bounds. p.add(N) is the first guard-page byte.
    unsafe {
        ptr::write_volatile(p.add(N), 0xFF);
    }

    // If we ever get here the fence failed.
    eprintln!("coffin: ERROR — overflow was not caught (this should be unreachable)");
    // Keep the buffer alive until after the bad write.
    std::hint::black_box(&buf);
}
