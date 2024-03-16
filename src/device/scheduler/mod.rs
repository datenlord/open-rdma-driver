use std::{collections::LinkedList, sync::Arc, thread::spawn};

use crossbeam_channel::{Receiver, Sender, TryRecvError};

use super::{ToCardCtrlRbDescSge, ToCardWorkRbDesc, ToCardWorkRbDescCommon};

use crate::types::{Key, Pmtu, Qpn};

const SCHEDULER_SIZE: usize = 1024 * 32; // 32KB

pub mod bench;
pub mod round_robin;

/// A descriptor scheduler that cut descriptor into `SCHEDULER_SIZE` size and schedule with a strategy.
#[allow(dead_code)]
pub(crate) struct DescriptorScheduler {
    sender: Sender<ToCardWorkRbDesc>,
    receiver: Receiver<ToCardWorkRbDesc>,
    strategy: Arc<dyn SchedulerStrategy>,
    thread_handler: std::thread::JoinHandle<()>,
}

pub trait SchedulerStrategy: Send + Sync {
    fn push(&self, qpn: Qpn, desc: LinkedList<ToCardWorkRbDesc>);

    fn pop(&self) -> Option<ToCardWorkRbDesc>;

    fn is_empty(&self) -> bool;
}

struct SGList {
    pub data: [ToCardCtrlRbDescSge; 4],
    pub cur_level: u32,
    pub len: u32,
}

impl Default for SGList {
    fn default() -> Self {
        Self {
            data: [
                ToCardCtrlRbDescSge {
                    addr: 0,
                    len: 0,
                    key: Key::default(),
                },
                ToCardCtrlRbDescSge {
                    addr: 0,
                    len: 0,
                    key: Key::default(),
                },
                ToCardCtrlRbDescSge {
                    addr: 0,
                    len: 0,
                    key: Key::default(),
                },
                ToCardCtrlRbDescSge {
                    addr: 0,
                    len: 0,
                    key: Key::default(),
                },
            ],
            cur_level: 0,
            len: 0,
        }
    }
}

impl DescriptorScheduler {
    pub fn new(strat: Arc<dyn SchedulerStrategy>) -> Self {
        let (sender, receiver) = crossbeam_channel::unbounded();
        let strategy: Arc<dyn SchedulerStrategy> = strat.clone();
        let thread_receiver = receiver.clone();
        let thread_handler = spawn(move || loop {
            let desc = match thread_receiver.try_recv() {
                Ok(desc) => Some(desc),
                Err(TryRecvError::Empty) => None,
                Err(TryRecvError::Disconnected) => return,
            };
            if let Some(desc) = desc {
                let dqpn = get_to_card_desc_common(&desc).dqpn;
                let splited_descs = split_descriptor(desc);
                strategy.push(dqpn, splited_descs);
            }
        });
        Self {
            sender,
            strategy: strat,
            thread_handler,
            receiver,
        }
    }

    pub fn push(self: &Arc<Self>, desc: ToCardWorkRbDesc) {
        match self.sender.send(desc) {
            Ok(_) => {}
            Err(e) => {
                eprintln!("Error when sending descriptor: {:?}", e);
                panic!();
            }
        }
    }

    pub fn pop(self: &Arc<Self>) -> Option<ToCardWorkRbDesc> {
        self.strategy.pop()
    }
}

#[allow(dead_code)]
fn get_first_schedule_segment_length(va: u64) -> u32 {
    let offset = va % SCHEDULER_SIZE as u64;
    if offset == 0 {
        SCHEDULER_SIZE as u32
    } else {
        (SCHEDULER_SIZE as u32) - offset as u32
    }
}

fn get_to_card_desc_common(desc: &ToCardWorkRbDesc) -> &ToCardWorkRbDescCommon {
    match desc {
        ToCardWorkRbDesc::Read(req) => &req.common,
        ToCardWorkRbDesc::Write(req) => &req.common,
        ToCardWorkRbDesc::WriteWithImm(req) => &req.common,
        ToCardWorkRbDesc::ReadResp(req) => &req.common,
    }
}

#[allow(dead_code)]
fn cut_from_sgl(mut length: u32, origin_sgl: &mut SGList) -> SGList {
    let mut current_level = origin_sgl.cur_level as usize;
    let mut new_sgl = SGList::default();
    let mut new_sgl_level: usize = 0;
    while (current_level as u32) < origin_sgl.len {
        if origin_sgl.data[current_level].len >= length {
            let addr = origin_sgl.data[current_level].addr;
            new_sgl.data[new_sgl_level] = ToCardCtrlRbDescSge {
                addr,
                len: length,
                key: origin_sgl.data[current_level].key,
            };
            new_sgl.len = new_sgl_level as u32 + 1;
            origin_sgl.data[current_level].addr += length as u64;
            origin_sgl.data[current_level].len -= length;
            if origin_sgl.data[current_level].len == 0 {
                current_level += 1;
            }
            origin_sgl.cur_level = current_level as u32;
            return new_sgl;
        } else {
            // check next level
            let addr = origin_sgl.data[current_level].addr as *mut u8;
            new_sgl.data[new_sgl_level] = ToCardCtrlRbDescSge {
                addr: addr as u64,
                len: origin_sgl.data[current_level].len,
                key: origin_sgl.data[current_level].key,
            };
            new_sgl_level += 1;
            length -= origin_sgl.data[current_level].len;
            origin_sgl.data[current_level].len = 0;
            current_level += 1;
        }
    }
    unreachable!("The length is too long");
}

/// Split the descriptor into multiple descriptors if it is greater than the `SCHEDULER_SIZE` size.
pub fn split_descriptor(_desc: ToCardWorkRbDesc) -> LinkedList<ToCardWorkRbDesc> {
    todo!()
    // match desc {
    //     ToCardWorkRbDesc::Request(mut req) => {
    //         if (req.common_header.total_len as usize) < SCHEDULER_SIZE {
    //             let mut list = LinkedList::new();
    //             list.push_back(ToCardWorkRbDesc::Request(req));
    //             return list;
    //         }
    //         let mut descs = LinkedList::new();
    //         let mut this_length = get_first_schedule_segment_length(req.raddr);
    //         let mut remain_data_length = req.common_header.total_len;
    //         let mut current_sgl_level = 0;
    //         let mut current_va = req.raddr;
    //         let mut base_psn: u32 = req.psn;
    //         while remain_data_length > 0 {
    //             let mut new_desc = req.clone();
    //             let new_sgl = cut_from_sgl(this_length, &mut req.sgl, &mut current_sgl_level);
    //             new_desc.sgl = new_sgl;
    //             new_desc.common_header.total_len = this_length;
    //             new_desc.raddr = current_va;
    //             new_desc.psn = base_psn;
    //             base_psn = recalculate_psn(&new_desc, base_psn);
    //             descs.push_back(ToCardWorkRbDesc::Request(new_desc));

    //             current_va += this_length as u64;
    //             remain_data_length -= this_length;
    //             this_length = if remain_data_length > SCHEDULER_SIZE as u32 {
    //                 SCHEDULER_SIZE as u32
    //             } else {
    //                 remain_data_length
    //             };
    //         }
    //         // The above code guarantee there at least 2 descriptors in the list
    //         let ToCardWorkRbDesc::Request(req) = descs.front_mut().unwrap();
    //         req.common_header.is_first = true;
    //         let ToCardWorkRbDesc::Request(req) = descs.back_mut().unwrap();
    //         req.common_header.is_last = true;
    //         descs
    //     }
    // }
}

/// Recalculate the PSN of the descriptor
///
/// # Example
/// base_psn = 0
/// desc.raddr = 4095
/// pmtu = 4096
/// desc.common_header.total_len = 4096 * 4
///
/// so the first_packet_length = 4096 - 4095 = 1
/// then the psn = 0 + ceil((4096 * 4 - first_packet_length),4096) = 4
/// That means we will send 5 packets in total(psn=0,1,2,3,4)
/// And the next psn will be 5
#[allow(dead_code)]
fn recalculate_psn(desc: &ToCardWorkRbDesc, base_psn: u32) -> u32 {
    let common = get_to_card_desc_common(desc);
    let pmtu = get_pmtu(&common.pmtu);
    let total_len = common.total_len;
    let first_packet_length = get_first_packet_length(common.raddr, pmtu);
    // first packet psn = base_psn
    // so the total psn = base_psn + (desc.common_header.total_len - first_packet_length) / pmtu + 1
    let last_packet_psn = base_psn + (total_len - first_packet_length).div_ceil(pmtu);
    last_packet_psn + 1
}

/// Get the length of the first packet.
///
/// A buffer will be divided into multiple packets if any slice is crossed the boundary of pmtu
/// For example, if pmtu = 256 and va = 254, then the first packet can be at most 2 bytes.
/// If pmtu = 256 and va = 256, then the first packet can be at most 256 bytes.
#[inline]
pub fn get_first_packet_length(va: u64, pmtu: u32) -> u32 {
    let offset = va % pmtu as u64;
    if offset == 0 {
        pmtu
    } else {
        pmtu - offset as u32
    }
}

/// Convert Pmtu enumeration to u32
#[inline]
fn get_pmtu(pmtu: &Pmtu) -> u32 {
    match pmtu {
        Pmtu::Mtu256 => 256,
        Pmtu::Mtu512 => 512,
        Pmtu::Mtu1024 => 1024,
        Pmtu::Mtu2048 => 2048,
        Pmtu::Mtu4096 => 4096,
    }
}

#[cfg(test)]
mod test {
    use std::collections::LinkedList;

    use crate::device::ToCardCtrlRbDescSge;

    use crate::types::Key;

    use super::SGList;

    pub struct SGListBuilder {
        sg_list: Vec<ToCardCtrlRbDescSge>,
    }

    impl SGListBuilder {
        pub fn new() -> Self {
            SGListBuilder {
                sg_list: Vec::new(),
            }
        }

        pub fn with_sge(&mut self, addr: u64, len: u32, key: Key) -> &mut Self {
            self.sg_list.push(ToCardCtrlRbDescSge { addr, len, key });
            self
        }

        pub fn build(&self) -> SGList {
            let mut sg_list = SGList::default();
            for sge in self.sg_list.iter() {
                sg_list.data[sg_list.len as usize] = sge.clone();
                sg_list.len += 1;
            }
            while sg_list.len < 4 {
                sg_list.data[sg_list.len as usize] = ToCardCtrlRbDescSge {
                    addr: 0,
                    len: 0,
                    key: Key::default(),
                };
            }
            sg_list
        }
    }

    #[test]
    fn test_helper_function_first_length() {
        let length = super::get_first_schedule_segment_length(0);
        assert_eq!(length, 1024 * 32);
        let length = super::get_first_schedule_segment_length(1024 * 29);
        assert_eq!(length, 1024 * 3);
        let length = super::get_first_schedule_segment_length(1024 * 32 + 1);
        assert_eq!(length, 1024 * 32 - 1);
    }
    #[test]
    fn test_cut_from_sgl() {
        let mut sgl = SGListBuilder::new()
            .with_sge(0, 1024, Key::default())
            .with_sge(2000, 1024, Key::default())
            .build();
        let new_sgl = super::cut_from_sgl(512, &mut sgl);
        assert_eq!(new_sgl.len, 1);
        assert_eq!(new_sgl.data[0].len, 512);
        assert_eq!(sgl.data[0].len, 512);
        assert_eq!(sgl.data[0].addr, 512);

        let new_sgl = super::cut_from_sgl(1024, &mut sgl);
        assert_eq!(new_sgl.len, 2);
        assert_eq!(new_sgl.data[0].addr, 512);
        assert_eq!(new_sgl.data[0].len, 512);
        assert_eq!(new_sgl.data[1].addr, 2000);
        assert_eq!(new_sgl.data[1].len, 512);
        assert_eq!(sgl.data[0].len, 0);
        assert_eq!(sgl.data[1].len, 512);
    }

    #[allow(dead_code)]
    fn convert_list_to_vec<T>(list: LinkedList<T>) -> Vec<T> {
        let mut vec = Vec::new();
        for i in list {
            vec.push(i);
        }
        vec
    }

    // #[test]
    // fn test_helper_function_split_descriptor() {
    //     let mut sgl = SGListBuilder::new()
    //         .with_sge(0, 1024 * 4, u32::from_be_bytes([1; 4]))
    //         .with_sge(0x10000, 1024 * 3, u32::from_be_bytes([2; 4]))
    //         .with_sge(0x20000, 1024 * 35, u32::from_be_bytes([3; 4]))
    //         .build();
    //     let base_psn = 1234;
    //         crate::device::ToCardWorkRbDesc::Request(crate::device::ToCardWorkRbDescRequest {
    //             common_header: crate::device::ToCardWorkRbDescCommonHeader {
    //                 total_len: 1024 * 42, // 42K
    //                 is_first: false,
    //                 is_last: false,
    //                 valid: true,
    //                 opcode: ToCardWorkRbDescOpcode::RdmaWrite,
    //                 extra_segment_cnt: 0,
    //                 is_success_or_need_signal_cplt: false,
    //             },
    //             dqpn: 0,
    //             raddr: 29 * 1024,
    //             sgl,
    //             rkey: [0; 4],
    //             dqp_ip: Ipv4Addr::new(0, 0, 0, 0),
    //             pmtu: crate::device::Pmtu::Mtu4096,
    //             flags: 0,
    //             qp_type: crate::device::QpType::Rc,
    //             sge_cnt: 0,
    //             psn: base_psn,
    //             mac_addr: [0; 6],
    //             imm: [0; 4],
    //         });
    //     let split_descs = convert_list_to_vec(split_descriptor(desc));
    //     assert_eq!(split_descs.len(), 3);
    //     // test desc 0
    //     let crate::device::ToCardWorkRbDesc::Request(desc0) = &split_descs[0];
    //     let desc0_psn = base_psn;
    //     assert_eq!(desc0.common_header.total_len, 1024 * 3);
    //     assert_eq!(desc0.raddr, 29 * 1024);
    //     assert_eq!(desc0.psn, desc0_psn);
    //     assert!(desc0.common_header.is_first);
    //     assert!(!desc0.common_header.is_last);
    //     assert_eq!(desc0.sgl.len, 1);
    //     assert_eq!(desc0.sgl.data[0].len, 3 * 1024);
    //     assert_eq!(desc0.sgl.data[0].laddr, 0);
    //     assert_eq!(desc0.sgl.data[0].lkey, [1; 4]);

    //     // test desc 1
    //     let crate::device::ToCardWorkRbDesc::Request(desc1) = &split_descs[1];
    //     let desc1_psn = recalculate_psn(desc0, base_psn);
    //     assert_eq!(desc1.common_header.total_len, 1024 * 32);
    //     assert_eq!(desc1.raddr, 32 * 1024);
    //     assert_eq!(desc1.psn, desc1_psn);
    //     assert!(!desc1.common_header.is_first);
    //     assert!(!desc1.common_header.is_last);
    //     assert_eq!(desc1.sgl.len, 3);
    //     assert_eq!(desc1.sgl.data[0].len, 1024);
    //     assert_eq!(desc1.sgl.data[0].laddr, 3 * 1024);
    //     assert_eq!(desc1.sgl.data[0].lkey, [1; 4]);
    //     assert_eq!(desc1.sgl.data[1].len, 3 * 1024);
    //     assert_eq!(desc1.sgl.data[1].laddr, 0x10000);
    //     assert_eq!(desc1.sgl.data[1].lkey, [2; 4]);
    //     assert_eq!(desc1.sgl.data[2].len, 28 * 1024);
    //     assert_eq!(desc1.sgl.data[2].laddr, 0x20000);
    //     assert_eq!(desc1.sgl.data[2].lkey, [3; 4]);

    //     // test desc 2
    //     let crate::device::ToCardWorkRbDesc::Request(desc2) = &split_descs[2];
    //     let desc2_psn = recalculate_psn(desc1, desc1_psn);
    //     assert_eq!(desc2.common_header.total_len, 1024 * 7);
    //     assert_eq!(desc2.raddr, 64 * 1024);
    //     assert_eq!(desc2.psn, desc2_psn);
    //     assert!(!desc2.common_header.is_first);
    //     assert!(desc2.common_header.is_last);
    //     assert_eq!(desc2.sgl.len, 1);
    //     assert_eq!(desc2.sgl.data[0].len, 7 * 1024);
    //     assert_eq!(desc2.sgl.data[0].laddr, 0x20000 + 28 * 1024);
    //     assert_eq!(desc2.sgl.data[0].lkey, [3; 4]);
    // }

    // #[test]
    // fn test_helper_recalculate_psn() {
    //     // base_psn = 0
    //     // desc.raddr = 4095
    //     // pmtu = 4096
    //     // desc.common_header.total_len = 4096 * 4
    //     let base_psn = 0;
    //     let desc = crate::device::ToCardWorkRbDescRequest {
    //         common_header: crate::device::ToCardWorkRbDescCommonHeader {
    //             total_len: 4096 * 4,
    //             is_first: true,
    //             is_last: true,
    //             valid: true,
    //             opcode: ToCardWorkRbDescOpcode::RdmaWrite,
    //             extra_segment_cnt: 0,
    //             is_success_or_need_signal_cplt: false,
    //         },
    //         dqpn: 0,
    //         raddr: 4095,
    //         sgl: crate::device::ScatterGatherList {
    //             data: [crate::device::ScatterGatherElement {
    //                 laddr: 0,
    //                 len: 1024 * 4,
    //                 lkey: [0; 4],
    //             }; 4],
    //             len: 3,
    //         },
    //         rkey: [0; 4],
    //         dqp_ip: Ipv4Addr::new(0, 0, 0, 0),
    //         pmtu: crate::device::Pmtu::Mtu4096,
    //         flags: 0,
    //         qp_type: crate::device::QpType::Rc,
    //         sge_cnt: 0,
    //         psn: 0,
    //         mac_addr: [0; 6],
    //         imm: [0; 4],
    //     };
    //     assert_eq!(recalculate_psn(&desc, base_psn), 5);

    //     // base_psn = 0
    //     // desc.raddr = 29*1024
    //     // pmtu = 4096
    //     // desc.common_header.total_len = 3*1024
    //     let desc = crate::device::ToCardWorkRbDescRequest {
    //         common_header: crate::device::ToCardWorkRbDescCommonHeader {
    //             total_len: 1024 * 3,
    //             is_first: true,
    //             is_last: true,
    //             valid: true,
    //             opcode: ToCardWorkRbDescOpcode::RdmaWrite,
    //             extra_segment_cnt: 0,
    //             is_success_or_need_signal_cplt: false,
    //         },
    //         dqpn: 0,
    //         raddr: 29 * 1024,
    //         sgl: crate::device::ScatterGatherList {
    //             data: [crate::device::ScatterGatherElement {
    //                 laddr: 0,
    //                 len: 1024 * 4,
    //                 lkey: [0; 4],
    //             }; 4],
    //             len: 3,
    //         },
    //         rkey: [0; 4],
    //         dqp_ip: Ipv4Addr::new(0, 0, 0, 0),
    //         pmtu: crate::device::Pmtu::Mtu4096,
    //         flags: 0,
    //         qp_type: crate::device::QpType::Rc,
    //         sge_cnt: 0,
    //         psn: 0,
    //         mac_addr: [0; 6],
    //         imm: [0; 4],
    //     };
    //     assert_eq!(recalculate_psn(&desc, base_psn), 1);
    // }

    // #[test]
    // fn test_scheduler() {
    //     let va = 29 * 1024;
    //     let length = 1024 * 32; // should cut into 2 segments: 29k - 32k, 32k - 61k
    //     let strategy = super::round_robin::RoundRobinStrategy::new();
    //     let scheduler = Arc::new(super::DescriptorScheduler::new(Arc::new(strategy)));
    //     let desc = ToCardWorkRbDesc::Request(crate::device::ToCardWorkRbDescRequest {
    //         common_header: crate::device::ToCardWorkRbDescCommonHeader {
    //             total_len: length,
    //             is_first: true,
    //             is_last: true,
    //             valid: true,
    //             opcode: ToCardWorkRbDescOpcode::RdmaWrite,
    //             extra_segment_cnt: 0,
    //             is_success_or_need_signal_cplt: false,
    //         },
    //         dqpn: 0,
    //         raddr: va,
    //         sgl: crate::device::ScatterGatherList {
    //             data: [crate::device::ScatterGatherElement {
    //                 laddr: 0,
    //                 len: length,
    //                 lkey: [0; 4],
    //             }; 4],
    //             len: 1,
    //         },
    //         rkey: [0; 4],
    //         dqp_ip: Ipv4Addr::new(0, 0, 0, 0),
    //         pmtu: crate::device::Pmtu::Mtu4096,
    //         flags: 0,
    //         qp_type: crate::device::QpType::Rc,
    //         sge_cnt: 0,
    //         psn: 0,
    //         mac_addr: [0; 6],
    //         imm: [0; 4],
    //     });
    //     scheduler.push(desc);
    //     // schedule the thread;
    //     // yield_now();
    //     sleep(std::time::Duration::from_millis(1));
    //     let desc1 = scheduler.pop();
    //     assert!(desc1.is_some());
    //     let desc1_length = match desc1.unwrap() {
    //         ToCardWorkRbDesc::Request(req) => req,
    //     }
    //     .common_header
    //     .total_len;
    //     assert_eq!(desc1_length, 1024 * 3);
    //     let desc2 = scheduler.pop();
    //     let desc2_length = match desc2.unwrap() {
    //         ToCardWorkRbDesc::Request(req) => req,
    //     }
    //     .common_header
    //     .total_len;
    //     assert_eq!(desc2_length, 1024 * 29);
    //     // assert!(scheduler.pop().is_none());
    // }
}
