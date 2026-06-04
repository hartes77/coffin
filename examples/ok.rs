//! Normal usage under Coffin: allocate, use, and free a variety of types.
//! Must run to completion and exit 0 — every allocation is page-fenced but
//! nothing ever touches a guard page.

#[global_allocator]
static ALLOC: coffin::Coffin = coffin::Coffin::new();

fn main() {
    println!("coffin: page size = {} bytes", coffin::page_size());
    println!("coffin: mode      = {:?}", coffin::mode());

    // Heap allocations of assorted sizes/alignments — all go through Coffin.
    let v: Vec<u64> = (0..1000).collect();
    let sum: u64 = v.iter().sum();

    let s = String::from("hello from inside the coffin");

    let boxed = Box::new([7u8; 4096]);

    let mut nested: Vec<Vec<u8>> = Vec::new();
    for i in 0..16 {
        nested.push(vec![i as u8; i * 13 + 1]);
    }

    println!("sum(0..1000)   = {sum}");
    println!("string         = {s:?}");
    println!("boxed[0]       = {}", boxed[0]);
    println!("nested buffers = {}", nested.len());

    // Everything drops here → dealloc → munmap. Clean exit expected.
    println!("coffin: ok — all allocations fenced, used, and freed");
}
