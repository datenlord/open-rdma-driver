use buddy_system_allocator::LockedHeap;
use libc;
use open_rdma_driver::{
    qp::{Pmtu, QpType},
    Device, Sge,
};
use std::time;
use std::{ffi::c_void, net::Ipv4Addr};

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
    eprintln!("Allocator created");

    let dev = Device::new_emulated("127.0.0.1:9875".parse().unwrap(), head_start_addr).unwrap();
    eprintln!("Device created");

    let pd = dev.alloc_pd().unwrap();
    eprintln!("PD allocated");

    let mut mr_buffer: Vec<u8> = Vec::new();
    mr_buffer.resize(8192, 0);

    let current_time = time::SystemTime::now()
        .duration_since(time::UNIX_EPOCH)
        .expect("Time went backwards");

    let timestamp = current_time.as_secs();

    mr_buffer[..8].copy_from_slice(&timestamp.to_le_bytes());
    let access_flag = 7;
    let mr = dev
        .reg_mr(
            pd.clone(),
            mr_buffer.as_mut_ptr() as u64,
            mr_buffer.len() as u32,
            1024 * 1024 * 2,
            access_flag,
        )
        .unwrap();
    eprintln!("MR registered");

    let qp = dev
        .create_qp(
            pd.clone(),
            QpType::Rc,
            Pmtu::Mtu4096,
            access_flag,
            0,
            Ipv4Addr::new(0x44, 0x33, 0x22, 0x11),
            [0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA],
        )
        .unwrap();
    eprintln!("QP created");

    let sge0 = Sge {
        addr: &mr_buffer[0] as *const u8 as u64,
        len: 1,
        key: mr.get_key(),
    };

    let sge1 = Sge {
        addr: &mr_buffer[1] as *const u8 as u64,
        len: 1,
        key: mr.get_key(),
    };

    let sge2 = Sge {
        addr: &mr_buffer[2] as *const u8 as u64,
        len: 1,
        key: mr.get_key(),
    };

    let sge3 = Sge {
        addr: &mr_buffer[3] as *const u8 as u64,
        len: 5,
        key: mr.get_key(),
    };
    dev.write(
        qp,
        &mr_buffer[8] as *const u8 as u64,
        mr.get_key(),
        0,
        sge0,
        Some(sge1),
        Some(sge2),
        Some(sge3),
    )
    .unwrap();

    eprintln!("Write req sent");

    assert!(mr_buffer[0..8] == mr_buffer[8..16]);

    dev.dereg_mr(mr).unwrap();
    eprintln!("MR deregistered");
}
