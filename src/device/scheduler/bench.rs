use std::{collections::LinkedList, net::Ipv4Addr};

use crate::device::{
    Pmtu, QpType, ScatterGatherElement, ScatterGatherList, ToCardWorkRbDesc,
    ToCardWorkRbDescCommonHeader, ToCardWorkRbDescOpcode, ToCardWorkRbDescRequest,
};

pub fn generate_random_descriptors(qpn: u32, num: usize) -> LinkedList<ToCardWorkRbDesc> {
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

pub fn generate_big_descriptor(size : u32) -> ToCardWorkRbDesc {
    ToCardWorkRbDesc::Request(ToCardWorkRbDescRequest {
        common_header: ToCardWorkRbDescCommonHeader {
            valid: true,
            opcode: ToCardWorkRbDescOpcode::RdmaWrite,
            is_last: true,
            is_first: true,
            extra_segment_cnt: 0,
            is_success_or_need_signal_cplt: false,
            total_len: size,
        },
        raddr: 0x0,
        rkey: 1234_u32.to_be_bytes(),
        dqp_ip: Ipv4Addr::new(127, 0, 0, 1),
        pmtu: Pmtu::Mtu1024,
        flags: 0,
        qp_type: QpType::Rc,
        sge_cnt: 0,
        psn: 0,
        mac_addr: [0u8; 6],
        dqpn: 4,
        imm: [0u8; 4],
        sgl: ScatterGatherList {
            data: [ScatterGatherElement {
                laddr: 0,
                len: size,
                lkey: 0x1234_u32.to_be_bytes(),
            }; 4],
            len: 1,
        },
    })
}
