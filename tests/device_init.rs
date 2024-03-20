use std::ffi::c_void;

use buddy_system_allocator::LockedHeap;

use open_rdma_driver::{Device, types::MemAccessTypeFlag};

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
            std::ptr::null_mut::<c_void>(),
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

#[test]
fn device_init() {
    let head_start_addr = unsafe { HEAP_START_ADDR };
    let _emulated =
        Device::new_emulated("127.0.0.1:9875".parse().unwrap(), head_start_addr).unwrap();
    let pd = _emulated.alloc_pd().unwrap();
    let access_flag = MemAccessTypeFlag::IbvAccessRemoteRead | MemAccessTypeFlag::IbvAccessRemoteWrite | MemAccessTypeFlag::IbvAccessLocalWrite;
    let mr = _emulated.reg_mr(pd, 0, 100, 4096, access_flag).unwrap();
    _emulated.dereg_mr(mr).unwrap();
    // let _hardware = Device::new_hardware().unwrap();
}
