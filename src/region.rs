//! Page-fenced region geometry and the raw `mmap`/`mprotect`/`munmap` plumbing.
//!
//! ## The placement contract (iron rule #2: alignment is sacred)
//!
//! The returned pointer ALWAYS respects `layout.align()` — violating it is UB.
//! We exploit the fact that for every real Rust type `size % align == 0`
//! (`size_of` is always a multiple of `align_of`), so the byte-exact fence is
//! free: the end of the buffer lands exactly on the guard page with zero padding.
//!
//! Only a hand-built `Layout` with `size % align != 0` forces padding, which we
//! fill with `POISON` (`0xDB`) and verify on free — never a silent downgrade.
//!
//! ## Why geometry is a pure function
//!
//! `region_geometry` depends only on `(size, align, mode, page)`. Both `alloc`
//! and `dealloc` receive the `Layout`, so `dealloc` recomputes the exact same
//! geometry and recovers the mapping base from the user pointer — no header, no
//! registry needed in Phase 1, and fully deterministic.

use crate::config::{mode, page_size, Mode};
use std::alloc::Layout;
use std::os::raw::c_void;

/// Fill byte for alignment padding between the buffer and the guard page.
pub const POISON: u8 = 0xDB;

#[inline]
fn round_up(x: usize, to: usize) -> usize {
    // `to` is always a power of two (page size / alignment).
    (x + to - 1) & !(to - 1)
}

#[inline]
fn align_down(x: usize, to: usize) -> usize {
    x & !(to - 1)
}

/// The resolved layout of one fenced mapping.
pub struct Geometry {
    /// Total length passed to `mmap`/`munmap`.
    pub map_len: usize,
    /// Offset of the guard page from the mapping base.
    pub guard_off: usize,
    /// Offset of the user pointer from the mapping base.
    pub user_off: usize,
    /// Bytes of poisoned padding between the buffer and the guard (Above mode).
    pub pad: usize,
}

/// Compute the fenced geometry for `layout` under the active mode (reads the
/// process-wide page size and mode).
pub fn region_geometry(layout: Layout) -> Geometry {
    geometry_for(layout.size(), layout.align(), mode(), page_size())
}

/// Pure geometry calculation — no globals, so it can be exhaustively tested for
/// both modes and arbitrary page sizes.
///
/// Above mode:  `[ data pages (RW) ............ buffer | pad ][ guard PROT_NONE ]`
/// Below mode:  `[ guard PROT_NONE ][ buffer ........... data pages (RW) ]`
pub fn geometry_for(size: usize, align: usize, mode: Mode, page: usize) -> Geometry {
    // Clamp to 1 so a (technically illegal) zero-size request never collapses
    // the data region onto the guard page.
    let size = size.max(1);

    // Over-aligned types beyond a page are exotic (max real align is typically
    // 16; pages are 4K/16K). Supporting them needs slack-mapping; out of scope
    // for Phase 1, so we assert the supported domain rather than silently
    // mis-aligning.
    assert!(
        align <= page,
        "Coffin: over-aligned allocation (align {align} > page {page}) not yet supported"
    );

    // Data must occupy whole pages so the guard sits on its own page.
    let data_bytes = round_up(size, page);

    match mode {
        Mode::Above => {
            // base is page-aligned, hence align-aligned (align <= page), so
            // align_down distributes over `base + x`. The buffer end touches the
            // guard boundary; any shortfall is poisoned padding.
            let user_off = align_down(data_bytes - size, align);
            let pad = (data_bytes - user_off) - size;
            Geometry {
                map_len: data_bytes + page,
                guard_off: data_bytes,
                user_off,
                pad,
            }
        }
        Mode::Below => {
            // Buffer starts on the first data page (page-aligned ⇒ satisfies any
            // align <= page). The guard precedes it; an underflow trips it.
            Geometry {
                map_len: page + data_bytes,
                guard_off: 0,
                user_off: page,
                pad: 0,
            }
        }
    }
}

/// `mmap` a fresh fenced region and return `(base, user_ptr)`, or `(null, null)`
/// on failure. The guard page is made `PROT_NONE`; Above-mode padding is poisoned.
///
/// # Safety
/// Caller must eventually `unmap_region` the returned base with the same layout.
pub unsafe fn map_region(layout: Layout, geom: &Geometry) -> (*mut u8, *mut u8) {
    let base = libc::mmap(
        std::ptr::null_mut(),
        geom.map_len,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE | libc::MAP_ANON,
        -1,
        0,
    );
    if base == libc::MAP_FAILED {
        return (std::ptr::null_mut(), std::ptr::null_mut());
    }
    let base = base as *mut u8;

    // Seal the guard page.
    if libc::mprotect(
        base.add(geom.guard_off) as *mut c_void,
        page_size(),
        libc::PROT_NONE,
    ) != 0
    {
        libc::munmap(base as *mut c_void, geom.map_len);
        return (std::ptr::null_mut(), std::ptr::null_mut());
    }

    let user = base.add(geom.user_off);

    // Poison the padding (only ever non-zero for the pathological size%align!=0
    // case in Above mode) so an overflow into it is caught on free.
    if geom.pad > 0 {
        let pad_start = user.add(layout.size().max(1));
        std::ptr::write_bytes(pad_start, POISON, geom.pad);
    }

    (base, user)
}

/// Verify the alignment-padding poison (Above mode, pathological size%align!=0).
/// A disturbed byte means an overflow landed in the padding — the one case the
/// live guard page can't catch byte-exactly. Reported via raw write (no alloc).
///
/// # Safety
/// `user_ptr`/`layout` must match a live `map_region` allocation.
pub unsafe fn check_padding(user_ptr: *mut u8, layout: Layout) {
    let geom = region_geometry(layout);
    if geom.pad == 0 {
        return;
    }
    let pad_start = user_ptr.add(layout.size().max(1));
    for i in 0..geom.pad {
        if *pad_start.add(i) != POISON {
            crate::report::raw_write(&[
                b"coffin: overflow into alignment padding detected at free\n",
            ]);
            break;
        }
    }
}

/// `mmap` `len` bytes of demand-zero RW memory for Coffin's own metadata
/// (registry arena, quarantine ring). Allocation-free. Returns null on failure.
///
/// # Safety
/// Caller owns the returned mapping and must not free it via Rust's allocator.
pub unsafe fn map_raw(len: usize) -> *mut u8 {
    let p = libc::mmap(
        std::ptr::null_mut(),
        len,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE | libc::MAP_ANON,
        -1,
        0,
    );
    if p == libc::MAP_FAILED {
        std::ptr::null_mut()
    } else {
        p as *mut u8
    }
}

/// Make `[addr, addr+len)` inaccessible (`PROT_NONE`). Used on free so the
/// whole region — buffer and guard alike — faults on any touch. Returns success.
///
/// # Safety
/// `addr`/`len` must describe a region currently owned by Coffin.
pub unsafe fn protect_none(addr: *mut u8, len: usize) -> bool {
    libc::mprotect(addr as *mut c_void, len, libc::PROT_NONE) == 0
}

/// `munmap` a region, returning its virtual address space to the OS.
///
/// # Safety
/// `addr`/`len` must describe a region currently owned by Coffin.
pub unsafe fn unmap(addr: *mut u8, len: usize) {
    libc::munmap(addr as *mut c_void, len);
}

#[cfg(test)]
mod tests {
    use super::*;

    // Iron rule #2: the user offset is ALWAYS a multiple of align, for every
    // mode, page size, and (size, align) pair — including the pathological
    // size % align != 0 case.
    #[test]
    fn alignment_is_always_respected() {
        for &page in &[4096usize, 16384] {
            for &align in &[1usize, 2, 4, 8, 16, 64, 4096] {
                if align > page {
                    continue;
                }
                for size in [1usize, 7, 8, 15, 16, 17, 64, 100, 4096, 4097, 40000] {
                    for mode in [Mode::Above, Mode::Below] {
                        let g = geometry_for(size, align, mode, page);
                        assert_eq!(
                            g.user_off % align,
                            0,
                            "user_off {} not aligned to {align} (size {size}, page {page}, {mode:?})",
                            g.user_off
                        );
                        // Guard page is always whole-page aligned.
                        assert_eq!(g.guard_off % page, 0);
                        assert_eq!(g.map_len % page, 0);
                    }
                }
            }
        }
    }

    // Above mode: buffer end + poison padding lands exactly on the guard page,
    // and padding is zero whenever size % align == 0 (i.e. all real types).
    #[test]
    fn above_mode_buffer_abuts_guard() {
        for &page in &[4096usize, 16384] {
            for &align in &[1usize, 8, 16, 64] {
                for size in [1usize, 8, 16, 17, 64, 100, 4096, 40000] {
                    let s = size.max(1);
                    let g = geometry_for(size, align, Mode::Above, page);
                    // buffer end + pad == guard offset
                    assert_eq!(g.user_off + s + g.pad, g.guard_off);
                    if s % align == 0 {
                        assert_eq!(g.pad, 0, "expected zero padding for size {s} align {align}");
                    }
                    assert!(g.pad < align.max(1));
                }
            }
        }
    }
}
