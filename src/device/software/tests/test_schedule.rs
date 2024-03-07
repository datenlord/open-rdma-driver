use std::{
    collections::LinkedList,
    net::Ipv4Addr,
    sync::{mpsc, Arc},
};

use rand::Rng;

use crate::device::{
    software::{
        logic::BlueRdmaLogicError,
        scheduler::{
            round_robin::RoundRobinStrategy, DescriptorScheduler, RDMALogicSendingWorkDesc,
            SchedulerStrategy,
        },
        types::Qpn,
    },
    Pmtu, QpType, ScatterGatherElement, ScatterGatherList, ToCardWorkRbDesc,
    ToCardWorkRbDescCommonHeader, ToCardWorkRbDescOpcode, ToCardWorkRbDescRequest,
};

fn convert_vec_to_linked_list<T>(vec: Vec<T>) -> std::collections::LinkedList<T> {
    vec.into_iter().collect()
}

fn descriptor_generators(qpn: u32, num: usize) -> LinkedList<ToCardWorkRbDesc> {
    let desc = ToCardWorkRbDescRequest {
        common_header: ToCardWorkRbDescCommonHeader {
            valid: true,
            opcode: ToCardWorkRbDescOpcode::RdmaWrite,
            is_last: true,
            is_first: true,
            extra_segment_cnt: 0,
            is_success_or_need_signal_cplt: false,
            total_len: 512,
        },
        raddr: 0x0,
        rkey: 1234_u32.to_be_bytes(),
        dqp_ip: Ipv4Addr::new(127, 0, 0, 1),
        pmtu: Pmtu::Mtu1024,
        flags: 0,
        qp_type: QpType::Rc,
        sge_cnt: 0,
        psn: 1234,
        mac_addr: [0u8; 6],
        dqpn: qpn,
        imm: [0u8; 4],
        sgl: ScatterGatherList {
            data: [ScatterGatherElement {
                laddr: 0x1000,
                len: 512,
                lkey: 0x1234_u32.to_be_bytes(),
            }; 4],
            len: 1,
        },
    };
    let mut ret = LinkedList::new();
    for _ in 0..num {
        ret.push_back(ToCardWorkRbDesc::Request(desc.clone()));
    }
    ret
}



#[test]
fn benchmark_round_robin_push() {
    // test how many insert and pop operations can be done in 1 second
    let round_robin = RoundRobinStrategy::new();

    // generate 10000 of Vec<ToCardWorkRbDesc> from qpn1-qpn10, each with random items
    let mut rng = rand::thread_rng();
    let mut qpn_descs = LinkedList::new();
    let total_start = std::time::Instant::now();
    for _ in 0..1000 {
        let qpn: u32 = rng.gen_range(0..1000);
        //     let number_of_descs = rng.gen_range(1..=1000000);
        let number_of_descs = 4096;
        // descriptor_generators(1, 4096);
        qpn_descs.push_back((Qpn::new(qpn), descriptor_generators(qpn, number_of_descs)));
    }
    // qpn_descs.push_back((Qpn::new(qpn), descriptor_generators(qpn, number_of_descs)));
    // let total_end = std::time::Instant::now();
    // let total_duration = total_end - total_start;
    // println!("Generated descriptors: {:?}", total_duration);
    // count the time of insert operations
    let mut counter = 0;
    // let total_start = std::time::Instant::now();
    while let Some((qpn, descs)) = qpn_descs.pop_front() {
        let len = descs.len();
        counter += len;
        // let start = std::time::Instant::now();
        round_robin.push(qpn, descs);
        // let end = std::time::Instant::now();
        // let duration = end - start;
        // println!("len = {},Insert operations: {:?}", len, duration);
    }
    let total_end = std::time::Instant::now();
    let total_duration = total_end - total_start;
    println!("Total Insert operations: {:?}", counter);
    println!(
        "Total Insert operations: {:?}",
        total_duration.as_secs_f64()
    );
}

fn benchmark_round_robin_pop() {
    // test how many insert and pop operations can be done in 1 second
    let round_robin = RoundRobinStrategy::new();

    // generate 100 of Vec<ToCardWorkRbDesc> from qpn1-qpn10, each with random items
    let mut rng = rand::thread_rng();
    let mut qpn_descs = vec![];
    let n = 1000;
    for _ in 0..n {
        let qpn = rng.gen_range(0..10);
        let number_of_descs = rng.gen_range(1000..=10000);
        qpn_descs.push((Qpn::new(qpn), descriptor_generators(qpn, number_of_descs)));
    }
    // count the time of insert operations
    for (qpn, descs) in qpn_descs {
        round_robin.push(qpn, descs);
    }
    let start = std::time::Instant::now();
    for _ in 0..n {
        round_robin.pop().unwrap();
    }
    let end = std::time::Instant::now();
    let duration = end - start;
    println!("Pop operations: {:?}", duration);
}
// #[test]
// fn test_scheduler(){
//     struct DummpyLogic;
//     unsafe impl Send for DummpyLogic {}
//     unsafe impl Sync for DummpyLogic {}
//     impl RDMALogicSendingWorkDesc for DummpyLogic {
//         fn send(&self, _desc: ToCardWorkRbDesc) -> Result<(), BlueRdmaLogicError> {
//             Ok(())
//         }
//     }
//     let round_robin = Arc::new(RoundRobinStrategy::new());
//     let logic = Arc::new(DummpyLogic);
//     let (sender, receiver) = mpsc::channel();
//     let mut scheduler = DescriptorScheduler::new(sender, receiver, round_robin, logic);
//     scheduler.start();
// }
