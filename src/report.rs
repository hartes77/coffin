//! Allocation-free output primitives.
//!
//! Everything here is safe to call from a place that must not allocate or lock
//! stdout (the alignment-padding check in Phase 1; the SIGSEGV handler in Phase
//! 3). We bypass `print!`/`eprintln!` entirely and go straight to `write(2)`.

use std::os::raw::c_void;

const HEX: &[u8; 16] = b"0123456789abcdef";

/// A `core::fmt::Write` sink that streams straight to a file descriptor via
/// `write(2)`, without allocating. Lets us print `Display` types (e.g.
/// backtrace's demangling `SymbolName`, or formatted annotation lines) in the
/// signal handler without building a `String`.
pub struct FdWriter(pub i32);

impl core::fmt::Write for FdWriter {
    #[inline]
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        raw_write_fd(self.0, &[s.as_bytes()]);
        Ok(())
    }
}

/// Write a byte slice verbatim to stderr.
#[inline]
pub fn write_str(s: &[u8]) {
    raw_write(&[s]);
}

/// Write `v` as `0x…` hex (no leading zeros), formatting into a stack buffer.
/// Allocation-free, async-signal-safe.
pub fn write_hex(v: usize) {
    let mut buf = [0u8; 2 + 16];
    buf[0] = b'0';
    buf[1] = b'x';
    let n;
    if v == 0 {
        buf[2] = b'0';
        n = 3;
    } else {
        let nibbles = ((usize::BITS - v.leading_zeros()) as usize).div_ceil(4);
        for i in 0..nibbles {
            let shift = (nibbles - 1 - i) * 4;
            buf[2 + i] = HEX[(v >> shift) & 0xf];
        }
        n = 2 + nibbles;
    }
    raw_write(&[&buf[..n]]);
}

/// Write `v` as decimal into a stack buffer. Allocation-free.
pub fn write_dec(mut v: usize) {
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    if v == 0 {
        raw_write(&[b"0"]);
        return;
    }
    while v > 0 {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    raw_write(&[&buf[i..]]);
}

/// Write a sequence of byte slices to `STDERR_FILENO` (the human report).
#[inline]
pub fn raw_write(parts: &[&[u8]]) {
    raw_write_fd(libc::STDERR_FILENO, parts);
}

/// Write a sequence of byte slices to an arbitrary fd. No heap, no formatting,
/// no locks — just raw `write(2)` calls. Stdout (fd 1) is used for GitHub
/// Actions annotations; stderr (fd 2) for the human report.
#[inline]
pub fn raw_write_fd(fd: i32, parts: &[&[u8]]) {
    for p in parts {
        let mut off = 0usize;
        while off < p.len() {
            // SAFETY: writing a valid slice range to the given fd.
            let n = unsafe { libc::write(fd, p.as_ptr().add(off) as *const c_void, p.len() - off) };
            if n <= 0 {
                break; // EINTR/EAGAIN/closed — don't risk spinning in fragile contexts.
            }
            off += n as usize;
        }
    }
}
