//! Process-wide configuration, resolved exactly once and cached.
//!
//! Iron rule #3 (page size) and the env lookups here run *from inside the global
//! allocator on the very first allocation*. They therefore MUST NOT allocate, or
//! we'd recurse into `Coffin` before it is ready. That is why we read the
//! environment via raw `libc::getenv` (no `String`) and the page size via
//! `sysconf` — both allocation-free — and cache them in `OnceLock`.

use std::ffi::CStr;
use std::os::raw::c_char;
use std::sync::OnceLock;

/// Where the guard page sits relative to the user buffer.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    /// Guard page *after* the buffer — catches buffer overflows (default).
    Above,
    /// Guard page *before* the buffer — catches buffer underflows.
    Below,
}

static PAGE_SIZE: OnceLock<usize> = OnceLock::new();
static MODE: OnceLock<Mode> = OnceLock::new();
static MAX_LIVE: OnceLock<usize> = OnceLock::new();
static QUARANTINE: OnceLock<usize> = OnceLock::new();
static SYMBOLIZE: OnceLock<bool> = OnceLock::new();

/// Default number of registry slots (rounded up to a power of two for masking).
const DEFAULT_MAX_LIVE: usize = 1 << 20; // 1_048_576
/// Default number of freed regions kept PROT_NONE before recycling their VA.
const DEFAULT_QUARANTINE: usize = 4096;

#[inline]
fn next_pow2(x: usize) -> usize {
    if x <= 1 {
        1
    } else {
        1usize << (usize::BITS - (x - 1).leading_zeros())
    }
}

/// Parse a `usize` from an env var via raw `getenv` (no allocation). Returns
/// `default` if unset or unparsable.
fn parse_usize_env(key: &[u8], default: usize) -> usize {
    debug_assert_eq!(*key.last().unwrap(), 0, "key must be NUL-terminated");
    // SAFETY: key is NUL-terminated; getenv does not allocate.
    let val = unsafe { libc::getenv(key.as_ptr() as *const c_char) };
    if val.is_null() {
        return default;
    }
    // SAFETY: getenv returned a valid NUL-terminated C string.
    let bytes = unsafe { CStr::from_ptr(val) }.to_bytes();
    let mut n: usize = 0;
    let mut seen = false;
    for &b in bytes {
        if b.is_ascii_digit() {
            seen = true;
            n = n.saturating_mul(10).saturating_add((b - b'0') as usize);
        } else {
            break;
        }
    }
    if seen && n > 0 {
        n
    } else {
        default
    }
}

/// System page size (4096 on Linux x86_64, 16384 on Apple Silicon), queried
/// once via `sysconf(_SC_PAGESIZE)` and cached. NEVER hardcoded (iron rule #3).
#[inline]
pub fn page_size() -> usize {
    *PAGE_SIZE.get_or_init(|| {
        // SAFETY: sysconf is async-signal-safe and does not allocate.
        let v = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        // sysconf returns -1 on failure; fall back to a sane minimum that is
        // still a real page multiple on every supported target.
        if v <= 0 {
            4096
        } else {
            v as usize
        }
    })
}

/// Protection mode, read once from `COFFIN_PROTECT` (`above` | `below`).
#[inline]
pub fn mode() -> Mode {
    *MODE.get_or_init(|| {
        const KEY: &[u8] = b"COFFIN_PROTECT\0";
        // SAFETY: KEY is NUL-terminated; getenv does not allocate.
        let val = unsafe { libc::getenv(KEY.as_ptr() as *const c_char) };
        if val.is_null() {
            return Mode::Above;
        }
        // SAFETY: getenv returned a valid NUL-terminated C string.
        let bytes = unsafe { CStr::from_ptr(val) }.to_bytes();
        match bytes {
            b"below" | b"BELOW" => Mode::Below,
            _ => Mode::Above,
        }
    })
}

/// Number of registry slots, power-of-two (for index masking). From
/// `COFFIN_MAX_LIVE` (default 1_048_576). This bounds the live+quarantined set;
/// the arena is mmap'd virtually at this size but only demand-paged when touched.
#[inline]
pub fn max_live_slots() -> usize {
    *MAX_LIVE.get_or_init(|| next_pow2(parse_usize_env(b"COFFIN_MAX_LIVE\0", DEFAULT_MAX_LIVE)))
}

/// Number of freed regions kept in quarantine (PROT_NONE, VA reserved) before
/// the oldest is munmap'd and recycled. From `COFFIN_QUARANTINE` (default 4096).
#[inline]
pub fn quarantine_cap() -> usize {
    *QUARANTINE.get_or_init(|| parse_usize_env(b"COFFIN_QUARANTINE\0", DEFAULT_QUARANTINE).max(1))
}

/// Whether the SIGSEGV handler should attempt to symbolize the captured raw
/// instruction pointers. Opt-in (`COFFIN_SYMBOLIZE=1`) because symbolization
/// allocates and is NOT async-signal-safe — the raw-IP baseline is always safe.
#[inline]
pub fn symbolize() -> bool {
    *SYMBOLIZE.get_or_init(|| {
        const KEY: &[u8] = b"COFFIN_SYMBOLIZE\0";
        // SAFETY: NUL-terminated key; getenv does not allocate.
        let val = unsafe { libc::getenv(KEY.as_ptr() as *const c_char) };
        if val.is_null() {
            return false;
        }
        // SAFETY: getenv returned a valid C string.
        matches!(
            unsafe { CStr::from_ptr(val) }.to_bytes(),
            b"1" | b"true" | b"yes"
        )
    })
}
