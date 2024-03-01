use buddy_system_allocator::LockedHeap;
use libc;
use open_rdma_driver::Device;
use std::ffi::c_void;

const ORDER: usize = 32;
const SHM_PATH: &str = "/bluesim1\0";

#[macro_use]
extern crate ctor;

/// Use `LockedHeap` as global allocator
#[global_allocator]
static HEAP_ALLOCATOR: LockedHeap<ORDER> = LockedHeap::<ORDER>::new();
const HEAP_BLOCK_SIZE: usize = 1024 * 1024 * 64;

static mut HEAP_START_ADDR: usize = 0;

#[ctor]
fn init_global_allocator() {
    unsafe {
        let shm_fd = libc::shm_open(
            SHM_PATH.as_ptr() as *const libc::c_char,
            libc::O_RDWR,
            0o600,
        );

        let heap = libc::mmap(
            0 as *mut c_void,
            1024 * 1024 * 1024,
            libc::PROT_EXEC | libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            shm_fd,
            0,
        );

        HEAP_START_ADDR = heap as usize;

        HEAP_ALLOCATOR.lock().init(heap as usize, HEAP_BLOCK_SIZE);
    }
}

fn main() {
    let head_start_addr = unsafe { HEAP_START_ADDR };

    let dev = Device::new_emulated("127.0.0.1:1234".parse().unwrap(), head_start_addr).unwrap();
    eprintln!("Device created");

    let pd = dev.alloc_pd().unwrap();
    eprintln!("PD allocated");

    let mr = dev.reg_mr(pd, 0, 100, 4096, 12).unwrap();
    eprintln!("MR registered");

    dev.dereg_mr(mr).unwrap();
    eprintln!("MR deregistered");
}
