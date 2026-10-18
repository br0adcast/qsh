//! PAM offset backing for the shared metered test allocator.
//! Its GlobalAlloc defaults for zeroing/reallocation intentionally call this
//! allocator's alloc/dealloc, preserving the C-free ownership trap.
use std::ffi::CStr;
use std::ptr;

pub(crate) fn backing() -> &'static dyn std::alloc::GlobalAlloc {
    if offset_allocations() {
        &OffsetAllocator
    } else {
        // Use System's own alloc_zeroed/realloc in allocation qualification.
        &std::alloc::System
    }
}

/// Test-only backing allocator for PAM ownership controls. In a process started with
/// [`OFFSET_ENV`] set, every Rust allocation -- from the process's first
/// -- sits 16 bytes into a block whose header glibc's `free()` refuses
/// ("munmap_chunk(): invalid pointer"): Rust memory handed to the C
/// library's `free()` aborts, instead of passing because Rust's
/// allocator happens to be `malloc` here. Otherwise it is `System`.
/// Decided once, at the first allocation, so no block changes kind.
struct OffsetAllocator;
pub(crate) const OFFSET_ENV: &CStr = c"QSHD_TEST_OFFSET_ALLOCATIONS";
/// 0: not decided yet; 1: off; 2: on.
static OFFSET_MODE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);
const HEADER: usize = 16;
/// A size field no real chunk has: size 0 with IS_MMAPPED set.
const FAKE_SIZE: usize = 0x2;
/// An odd prev_size: `munmap_chunk`'s alignment check refuses it.
const FAKE_PREV: usize = 0x1;

pub(crate) fn offset_allocations() -> bool {
    use std::sync::atomic::Ordering::Relaxed;
    match OFFSET_MODE.load(Relaxed) {
        0 => {
            // SAFETY: `getenv` allocates nothing, and the first
            // allocation happens before any thread could change the
            // environment.
            let on = !unsafe { libc::getenv(OFFSET_ENV.as_ptr()) }.is_null();
            OFFSET_MODE.store(if on { 2 } else { 1 }, Relaxed);
            on
        }
        mode => mode == 2,
    }
}

// SAFETY: every block comes from `System`; an offset block is freed
// through the outer layout it was allocated with, and whether a block is
// offset never changes within a process.
unsafe impl std::alloc::GlobalAlloc for OffsetAllocator {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        use std::alloc::{Layout, System};
        if !offset_allocations() || layout.align() > HEADER {
            return unsafe { System.alloc(layout) };
        }
        let Ok(outer) = Layout::from_size_align(layout.size() + HEADER, HEADER) else {
            return ptr::null_mut();
        };
        let block = unsafe { System.alloc(outer) };
        if block.is_null() {
            return block;
        }
        unsafe {
            block.cast::<usize>().write(FAKE_PREV);
            block.add(8).cast::<usize>().write(FAKE_SIZE);
            block.add(HEADER)
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: std::alloc::Layout) {
        use std::alloc::{Layout, System};
        if offset_allocations() && layout.align() <= HEADER {
            unsafe {
                System.dealloc(
                    ptr.sub(HEADER),
                    Layout::from_size_align_unchecked(layout.size() + HEADER, HEADER),
                )
            }
        } else {
            unsafe { System.dealloc(ptr, layout) }
        }
    }
}
