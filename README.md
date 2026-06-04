# ⚰️ Coffin

[![CI](https://github.com/hartes77/coffin/actions/workflows/ci.yml/badge.svg)](https://github.com/hartes77/coffin/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/coffin.svg)](https://crates.io/crates/coffin)
[![docs.rs](https://img.shields.io/docsrs/coffin)](https://docs.rs/coffin)
[![license](https://img.shields.io/crates/l/coffin.svg)](#license)

**A page-fencing global allocator for Rust that turns silent memory corruption
into a deterministic crash with a post-mortem.**

Coffin is the spiritual heir to [Electric Fence](https://en.wikipedia.org/wiki/Electric_Fence),
rebuilt for Rust: production-grade, lock-free for readers, and portable across
Linux (x86-64) and macOS (Apple Silicon) from day one.

Every allocation gets its own dedicated pages with an adjacent **guard page**
(`PROT_NONE`). When you write one byte past the end of a buffer, you step onto
the guard page and the process faults **immediately, at the exact byte** — not
"some time later, somewhere else." When you free a buffer, Coffin seals it
`PROT_NONE` and refuses to reuse its address until it ages out of quarantine, so
**use-after-free faults at the exact address too**.

On the fault, Coffin prints what happened, where the memory was allocated, and
(for use-after-free) where it was freed.

---

## Quick start

```rust
#[global_allocator]
static ALLOC: coffin::Coffin = coffin::Coffin::new();

fn main() {
    // Optional but recommended on macOS: re-assert the handler from main so
    // wild-pointer SIGSEGVs are caught even if std armed its own first.
    coffin::arm();

    let v = vec![0u8; 64];
    unsafe { *(v.as_ptr() as *mut u8).add(64) = 1; } // 💥 caught on the guard page
}
```

## What a report looks like

```
========================= COFFIN =========================
  signal        : SIGBUS (10)
  fault address : 0x104d23fc0
  fault         : USE-AFTER-FREE
  region        : base 0x104d20000 .. 0x104d28000 (32768 bytes mapped)
  user buffer   : 0x104d23fc0  size 64  align 8
  offset        : 0 byte(s) into the freed buffer
  allocated at  :
      0x104aa0664
        coffin::coffin_alloc
        uaf::main
          at examples/uaf.rs:20
  freed at      :
      0x104a99d80
        coffin::coffin_dealloc
        uaf::main
          at examples/uaf.rs:25
==========================================================
```

(Set `COFFIN_SYMBOLIZE=1` for the demangled names + `file:line` shown above;
without it you still get the raw instruction pointers.)

## Fault types it classifies

| Fault            | When                                                      |
|------------------|-----------------------------------------------------------|
| `BUFFER OVERFLOW`  | Wrote past the end of a live buffer (default `above` mode) |
| `BUFFER UNDERFLOW` | Wrote before the start (when in `below` mode)             |
| `USE-AFTER-FREE`   | Touched a freed buffer still in quarantine                |
| `WILD POINTER`     | Dangling / foreign / corrupt pointer, no tracked region   |

## Configuration

All via environment variables, read once at startup:

| Variable            | Meaning                                                        | Default     |
|---------------------|----------------------------------------------------------------|-------------|
| `COFFIN_PROTECT`    | `above` (catch overflows) or `below` (catch underflows)        | `above`     |
| `COFFIN_MAX_LIVE`   | Registry slots, rounded up to a power of two (max tracked live) | `1048576`   |
| `COFFIN_QUARANTINE` | Freed regions kept sealed before their address is recycled     | `4096`      |
| `COFFIN_SYMBOLIZE`  | `1` to demangle/resolve the captured stacks in the report      | off         |

## How it works

- **Alignment is sacred.** The returned pointer always honors `layout.align()`.
  Because every real Rust type has `size % align == 0`, the buffer's end lands
  exactly on the guard page with zero padding — the fence is byte-exact for free.
- **Registry.** A fixed-slot arena, `mmap`'d once and demand-paged, tracks every
  allocation. Writers publish each slot with a `Release` store after filling it;
  the fault handler reads it **lock-free** with `Acquire`. No `HashMap`, no mutex
  on the read path.
- **Quarantine.** Freed regions are sealed `PROT_NONE` and parked in a bounded
  ring. Once the ring is full, the oldest region is `munmap`'d so the virtual
  address space is reclaimed (no blowing past `vm.max_map_count`). A use-after-free
  is therefore caught within a window of the last `COFFIN_QUARANTINE` frees.
- **Signal handler.** Catches `SIGSEGV` *and* `SIGBUS` (macOS often delivers the
  latter for `PROT_NONE`), runs on an alternate signal stack, classifies the
  fault with a linear scan, and writes the report with raw `write(2)` — no heap,
  no locks. Symbolization is the one async-unsafe step and is strictly opt-in.

## Why not AddressSanitizer?

You probably should use [AddressSanitizer](https://github.com/google/sanitizers/wiki/addresssanitizer)
when you can. **Coffin is not a replacement for ASan** — it's a different set of
trade-offs that wins in a few specific situations.

|                         | **Coffin**                                  | **AddressSanitizer**                          |
|-------------------------|---------------------------------------------|-----------------------------------------------|
| Toolchain               | **Stable Rust, drop-in `#[global_allocator]`** | Nightly (`-Zsanitizer=address`), recompile the world |
| What it instruments     | Heap allocations only                       | Heap **+ stack + globals**, and reads/writes  |
| Overflow precision      | **Exact byte** (hardware guard page)        | Redzone (caught, but not always the exact byte) |
| Use-after-free          | ✅ (within quarantine window)               | ✅ (within quarantine window)                 |
| Uninitialized reads     | ❌                                          | ❌ (that's MSan), but ASan catches more       |
| Memory overhead         | **High** — ≥1 page per allocation           | Lower — shadow memory (~2x)                    |
| Runs on a release build | ✅ just swap the allocator                  | Needs an instrumented rebuild of all deps     |
| Code size / auditability| ~1k lines, 2 deps, readable in an afternoon | Large C++ runtime                              |

**Reach for Coffin when** you want to drop a guard-page allocator into a
canary/CI/staging build on **stable Rust without recompiling your dependencies**,
and you want overflows to fault at the *exact* byte with a report that names the
alloc and free sites.

**Reach for ASan when** you can use nightly and rebuild, and you want broader
coverage (stack, globals, intra-object overflows) at lower memory cost.

**What Coffin does _not_ catch:** stack/global overflows, uninitialized reads,
intra-object overflows, and reads/writes that stay within the allocation's own
pages. It is heap-only and page-granular by design.

## ⚠️ This is a debugging tool, not a production allocator

Coffin uses **at least one page per allocation** (4 KiB on Linux, **16 KiB on
Apple Silicon**), plus a guard page. That is enormous overhead by design.

Run it in **CI, canary, staging, or a fuzzing harness** — anywhere you want
corruption to surface loudly and reproducibly. **Do not** use it as your
always-on production hot-path allocator.

## Examples

```bash
cargo run --example ok        # normal usage, exits 0
cargo run --example overflow  # 1-byte overflow  -> BUFFER OVERFLOW report
cargo run --example uaf       # use-after-free    -> USE-AFTER-FREE report
cargo run --example wild      # bogus pointer     -> WILD POINTER report
cargo run --example inspect   # non-crashing tour of the registry + quarantine

COFFIN_SYMBOLIZE=1 cargo run --example uaf   # with demangled alloc/free stacks
```

## License

MIT OR Apache-2.0
