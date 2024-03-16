use std::{collections::LinkedList, net::Ipv4Addr};

use crate::device::{
    ToCardCtrlRbDescSge, ToCardWorkRbDesc, ToCardWorkRbDescCommon, ToCardWorkRbDescWrite,
};
use crate::types::{Key, MemAccessTypeFlag, Pmtu, Psn, QpType, Qpn};

#[allow(unused)]
pub fn generate_random_descriptors(qpn: u32, num: usize) -> LinkedList<ToCardWorkRbDesc> {
    let desc = ToCardWorkRbDesc::Write(ToCardWorkRbDescWrite {
        common: ToCardWorkRbDescCommon {
            total_len: 512,
            raddr: 0x0,
            rkey: Key::new(1234_u32),
            dqp_ip: Ipv4Addr::new(127, 0, 0, 1),
            dqpn: Qpn::new(qpn),
            mac_addr: [0; 6],
            pmtu: Pmtu::Mtu1024,
            flags: MemAccessTypeFlag::IbvAccessNoFlags,
            qp_type: QpType::Rc,
            psn: Psn::new(1234),
        },
        is_last: true,
        is_first: true,
        sge0: ToCardCtrlRbDescSge {
            addr: 0x1000,
            len: 512,
            key: Key::new(0x1234_u32),
        },
        sge1: None,
        sge2: None,
        sge3: None,
    });
    let mut ret = LinkedList::new();
    for _ in 0..num {
        ret.push_back(desc.clone());
    }
    ret
}

#[allow(unused)]
pub fn generate_big_descriptor(size: u32) -> ToCardWorkRbDesc {
    ToCardWorkRbDesc::Write(ToCardWorkRbDescWrite {
        common: ToCardWorkRbDescCommon {
            total_len: size,
            raddr: 0x0,
            rkey: Key::new(1234_u32),
            dqp_ip: Ipv4Addr::new(127, 0, 0, 1),
            dqpn: Qpn::new(4),
            mac_addr: [0; 6],
            pmtu: Pmtu::Mtu1024,
            flags: MemAccessTypeFlag::IbvAccessNoFlags,
            qp_type: QpType::Rc,
            psn: Psn::new(1234),
        },
        is_last: true,
        is_first: true,
        sge0: ToCardCtrlRbDescSge {
            addr: 0x1000,
            len: size,
            key: Key::new(0x1234_u32),
        },
        sge1: None,
        sge2: None,
        sge3: None,
    })
}
