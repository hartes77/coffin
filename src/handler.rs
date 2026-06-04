//! The SIGSEGV / SIGBUS handler: turns a fault on a fenced page into a
//! deterministic, human-readable post-mortem.
//!
//! ## Async-signal-safety (iron rule #5)
//!
//! * **No locks.** Classification is a lock-free linear scan of the registry
//!   ([`Arena::classify`]); the handler never takes the writer spinlock.
//! * **No heap, no `println!`.** All output goes through `write(2)` via
//!   [`crate::report`], formatting integers into stack buffers.
//! * **Alternate signal stack.** Installed with `sigaltstack` + `SA_ONSTACK`,
//!   so the handler survives even a stack-overflow fault.
//! * **Symbolization is the one async-unsafe concession** — opt-in
//!   (`COFFIN_SYMBOLIZE=1`), emitted only AFTER the always-safe raw baseline,
//!   and with the reentrancy guard forced on so any allocation it does is
//!   served by the system allocator (never re-entering Coffin's spinlock).

use crate::registry::{self, FaultKind};
use crate::report::{write_dec as dec, write_hex as hex, write_str as put};
use std::os::raw::{c_int, c_void};
use std::sync::Once;

static ALT_STACK: Once = Once::new();

/// Install (or re-install) the fault handler.
///
/// The alternate signal stack and config caches are set up exactly once; the
/// signal *dispositions* are (re)asserted on every call. This matters on macOS:
/// Rust's std runtime installs its own SIGSEGV stack-overflow guard during
/// startup, and if Coffin's first allocation happens pre-`main`, std would clobber
/// our SIGSEGV disposition afterwards. Re-asserting (e.g. from [`crate::arm`] at
/// the top of `main`) guarantees Coffin wins. Idempotent and cheap.
pub fn install() {
    ALT_STACK.call_once(|| unsafe {
        // Pre-resolve config so the handler never lazily initializes anything.
        let _ = crate::page_size();
        let _ = crate::config::symbolize();

        // Alternate signal stack — lets the handler run even on stack overflow.
        let size = core::cmp::max(libc::SIGSTKSZ, 64 * 1024);
        let mem = crate::region::map_raw(size);
        if !mem.is_null() {
            let ss = libc::stack_t {
                ss_sp: mem as *mut c_void,
                ss_flags: 0,
                ss_size: size,
            };
            libc::sigaltstack(&ss, core::ptr::null_mut());
        }
    });

    // SAFETY: standard sigaction registration with a valid handler pointer.
    unsafe {
        let mut sa: libc::sigaction = core::mem::zeroed();
        sa.sa_sigaction = handle as *const () as libc::sighandler_t;
        sa.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK;
        libc::sigemptyset(&mut sa.sa_mask);
        // Both signals: Linux usually delivers SIGSEGV, macOS often SIGBUS.
        libc::sigaction(libc::SIGSEGV, &sa, core::ptr::null_mut());
        libc::sigaction(libc::SIGBUS, &sa, core::ptr::null_mut());
    }
}

/// Extract the faulting address from `siginfo`. Field on macOS, accessor on
/// Linux.
#[inline]
unsafe fn fault_addr(info: *const libc::siginfo_t) -> usize {
    #[cfg(target_os = "macos")]
    {
        (*info).si_addr as usize
    }
    #[cfg(target_os = "linux")]
    {
        (*info).si_addr() as usize
    }
}

#[inline]
fn sig_name(sig: c_int) -> &'static [u8] {
    match sig {
        libc::SIGSEGV => b"SIGSEGV",
        libc::SIGBUS => b"SIGBUS",
        _ => b"signal",
    }
}

/// The actual handler. `extern "C"` with `SA_SIGINFO` signature.
extern "C" fn handle(sig: c_int, info: *mut libc::siginfo_t, _ctx: *mut c_void) {
    let addr = unsafe { fault_addr(info) };
    report(sig, addr);

    // Terminate with the *original* signal and dump core. Re-`raise`ing here is
    // useless — the signal is blocked while its own handler runs. The classic
    // idiom is to restore the default disposition and simply RETURN: the
    // faulting instruction re-executes, faults again, and now `SIG_DFL` kills
    // the process with the true signal (SIGSEGV/SIGBUS) and a core dump.
    unsafe {
        libc::signal(libc::SIGSEGV, libc::SIG_DFL);
        libc::signal(libc::SIGBUS, libc::SIG_DFL);
    }
}

fn report(sig: c_int, addr: usize) {
    let symbolize = crate::config::symbolize();
    // Force the reentrancy guard on for the rest of the handler: if
    // symbolization allocates, it is routed to the system allocator instead of
    // re-entering Coffin (and its spinlock).
    if symbolize {
        crate::force_guard();
    }

    // Emit the always-safe basics FIRST — signal and faulting address need no
    // registry access, so they survive even if the lock-free scan below hits a
    // torn entry. Only then run the classification scan.
    put(b"\n========================= COFFIN =========================\n");
    put(b"  signal        : ");
    put(sig_name(sig));
    put(b" (");
    dec(sig as usize);
    put(b")\n");
    put(b"  fault address : ");
    hex(addr);
    put(b"\n");

    let info = registry::try_get().map(|a| a.classify(addr));

    put(b"  fault         : ");
    match info.as_ref().map(|i| i.kind) {
        Some(FaultKind::Overflow) => put(b"BUFFER OVERFLOW (write past end of allocation)\n"),
        Some(FaultKind::Underflow) => put(b"BUFFER UNDERFLOW (write before allocation)\n"),
        Some(FaultKind::UseAfterFree) => put(b"USE-AFTER-FREE\n"),
        Some(FaultKind::LiveRegion) => put(b"FAULT INSIDE LIVE REGION (unexpected)\n"),
        _ => put(b"WILD POINTER (no tracked region)\n"),
    }

    match info {
        Some(fi) if fi.kind != FaultKind::Wild => {
            put(b"  region        : base ");
            hex(fi.base);
            put(b" .. ");
            hex(fi.base + fi.total_len);
            put(b" (");
            dec(fi.total_len);
            put(b" bytes mapped)\n");

            put(b"  user buffer   : ");
            hex(fi.user_ptr);
            put(b"  size ");
            dec(fi.size);
            put(b"  align ");
            dec(fi.align);
            put(b"\n");

            match fi.kind {
                FaultKind::Overflow => {
                    put(b"  overflow      : ");
                    dec(addr.wrapping_sub(fi.user_ptr + fi.size));
                    put(b" byte(s) past the end of the buffer\n");
                }
                FaultKind::Underflow => {
                    put(b"  underflow     : ");
                    dec(fi.user_ptr.wrapping_sub(addr));
                    put(b" byte(s) before the start of the buffer\n");
                }
                FaultKind::UseAfterFree => {
                    put(b"  offset        : ");
                    dec(addr.wrapping_sub(fi.user_ptr));
                    put(b" byte(s) into the freed buffer\n");
                }
                _ => {}
            }

            // Allocation site.
            put(b"  allocated at  :\n");
            dump_stack(fi.slot, false, symbolize);

            // Free site (only meaningful for use-after-free).
            if fi.kind == FaultKind::UseAfterFree {
                put(b"  freed at      :\n");
                dump_stack(fi.slot, true, symbolize);
            }
        }
        _ => {
            put(b"  (address is not inside any live or quarantined allocation)\n");
        }
    }

    if !symbolize {
        put(b"  hint          : set COFFIN_SYMBOLIZE=1 for symbol names + file:line\n");
    }
    put(b"==========================================================\n");
}

/// Print one captured stack: raw IPs always, plus best-effort symbols if asked.
fn dump_stack(slot: usize, free: bool, symbolize: bool) {
    let arena = match registry::try_get() {
        Some(a) => a,
        None => return,
    };
    let ips = arena.read_ips(slot, free);
    let mut any = false;
    for &ip in ips.iter() {
        if ip == 0 {
            continue;
        }
        any = true;
        put(b"      ");
        hex(ip);
        put(b"\n");
        if symbolize {
            symbolize_ip(ip);
        }
    }
    if !any {
        put(b"      <no frames captured>\n");
    }
}

/// Best-effort, async-UNSAFE symbolization (allocates). Guarded by the opt-in
/// flag and the forced reentrancy guard. Failures are silent — the raw IP above
/// is the authoritative record.
fn symbolize_ip(ip: usize) {
    // `resolve` may allocate and is NOT async-signal-safe; we have forced the
    // reentrancy guard so those allocations go to the system allocator. We
    // accept the async-unsafety here per the constitution (opt-in only).
    backtrace::resolve(ip as *mut c_void, |sym| {
        if let Some(name) = sym.name() {
            use core::fmt::Write;
            put(b"        ");
            // `SymbolName`'s Display demangles; stream it to stderr (no heap).
            let _ = write!(crate::report::StderrFmt, "{name}");
            put(b"\n");
        }
        if let (Some(file), Some(line)) = (sym.filename(), sym.lineno()) {
            if let Some(fs) = file.to_str() {
                put(b"          at ");
                put(fs.as_bytes());
                put(b":");
                dec(line as usize);
                put(b"\n");
            }
        }
    });
}
