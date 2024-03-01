#![allow(unused)]

use std::{net::Ipv4Addr, ops::Range};

pub(crate) enum ToCardCtrlRbDesc {
    UpdateMrTable(ToCardCtrlRbDescUpdateMrTable),
    UpdatePageTable(ToCardCtrlRbDescUpdatePageTable),
    QpManagement(ToCardCtrlRbDescQpManagement),
}

pub(crate) enum ToHostCtrlRbDesc {
    UpdateMrTable(ToHostCtrlRbDescUpdateMrTable),
    UpdatePageTable(ToHostCtrlRbDescUpdatePageTable),
    QpManagement(ToHostCtrlRbDescQpManagement),
}

pub(crate) enum ToCardWorkRbDesc {
    Write(ToCardWorkRbDescWrite),
    WriteWithImm(ToCardWorkRbDescWriteWithImm),
    Read(ToCardWorkRbDescRead),
}

pub(crate) enum ToHostWorkRbDesc {
    Read(ToHostWorkRbDescRead),
    Write(ToHostWorkRbDescWrite),
    WriteWithImm(ToHostWorkRbDescWriteWithImm),
    Ack(ToHostWorkRbDescAck),
    Nack(ToHostWorkRbDescNack),
}

pub(crate) struct ToCardCtrlRbDescCommon {
    pub(crate) op_id: [u8; 4], // user_data
}

pub(crate) struct ToCardCtrlRbDescUpdateMrTable {
    pub(crate) common: ToCardCtrlRbDescCommon,
    pub(crate) addr: u64,
    pub(crate) len: u32,
    pub(crate) key: u32,
    pub(crate) pd_hdl: u32,
    pub(crate) acc_flags: u8,
    pub(crate) pgt_offset: u32,
}

pub(crate) struct ToCardCtrlRbDescUpdatePageTable {
    pub(crate) common: ToCardCtrlRbDescCommon,
    pub(crate) start_addr: u64,
    pub(crate) pgt_idx: u32,
    pub(crate) pgte_cnt: u32,
}

pub(crate) struct ToCardCtrlRbDescQpManagement {
    pub(crate) common: ToCardCtrlRbDescCommon,
    pub(crate) is_valid: bool,
    pub(crate) qpn: u32,
    pub(crate) pd_hdl: u32,
    pub(crate) qp_type: QpType,
    pub(crate) rq_acc_flags: u8,
    pub(crate) pmtu: Pmtu,
}

pub(crate) struct ToHostCtrlRbDescCommon {
    pub(crate) op_id: [u8; 4], // user_data
    pub(crate) is_success: bool,
}

pub(crate) struct ToHostCtrlRbDescUpdateMrTable {
    pub(crate) common: ToHostCtrlRbDescCommon,
}

pub(crate) struct ToHostCtrlRbDescUpdatePageTable {
    pub(crate) common: ToHostCtrlRbDescCommon,
}

pub(crate) struct ToHostCtrlRbDescQpManagement {
    pub(crate) common: ToHostCtrlRbDescCommon,
}

pub(crate) struct ToCardWorkRbDescCommon {
    pub(crate) is_last: bool,
    pub(crate) is_first: bool,
    pub(crate) total_len: u32,
    pub(crate) raddr: u64,
    pub(crate) rkey: u32,
    pub(crate) dqp_ip: Ipv4Addr,
    pub(crate) dqpn: u32,
    pub(crate) mac_addr: [u8; 6],
    pub(crate) pmtu: Pmtu,
    pub(crate) flags: u8,
    pub(crate) qp_type: QpType,
    pub(crate) psn: u32,
}

pub(crate) struct ToCardWorkRbDescWrite {
    pub(crate) common: ToCardWorkRbDescCommon,
    pub(crate) sge0: ToCardCtrlRbDescSge,
    pub(crate) sge1: Option<ToCardCtrlRbDescSge>,
    pub(crate) sge2: Option<ToCardCtrlRbDescSge>,
    pub(crate) sge3: Option<ToCardCtrlRbDescSge>,
}

pub(crate) struct ToCardWorkRbDescWriteWithImm {
    pub(crate) common: ToCardWorkRbDescCommon,
    pub(crate) imm: [u8; 4],
    pub(crate) sge0: ToCardCtrlRbDescSge,
    pub(crate) sge1: Option<ToCardCtrlRbDescSge>,
    pub(crate) sge2: Option<ToCardCtrlRbDescSge>,
    pub(crate) sge3: Option<ToCardCtrlRbDescSge>,
}

pub(crate) struct ToCardWorkRbDescRead {
    pub(crate) common: ToCardWorkRbDescCommon,
    pub(crate) sge: ToCardCtrlRbDescSge,
}

pub(crate) struct ToHostWorkRbDescCommon {
    pub(crate) status: ToHostWorkRbDescStatus,
    pub(crate) trans: ToHostWorkRbDescTransType,
    pub(crate) dqpn: u32,
}

pub(crate) struct ToHostWorkRbDescRead {
    pub(crate) common: ToHostWorkRbDescCommon,
    pub(crate) len: u32,
    pub(crate) laddr: u64,
    pub(crate) lkey: u32,
    pub(crate) raddr: u64,
    pub(crate) rkey: u32,
}

pub(crate) struct ToHostWorkRbDescWrite {
    pub(crate) common: ToHostWorkRbDescCommon,
    pub(crate) psn: u32,
    pub(crate) addr: u64,
    pub(crate) len: u32,
    pub(crate) key: u32,
}

pub(crate) struct ToHostWorkRbDescWriteWithImm {
    pub(crate) common: ToHostWorkRbDescCommon,
    pub(crate) psn: u32,
    pub(crate) imm: [u8; 4],
    pub(crate) addr: u64,
    pub(crate) len: u32,
    pub(crate) key: u32,
}

pub(crate) struct ToHostWorkRbDescAck {
    pub(crate) common: ToHostWorkRbDescCommon,
    pub(crate) msn: u32,
    pub(crate) value: u32,
    pub(crate) psn: u32,
}

pub(crate) struct ToHostWorkRbDescNack {
    pub(crate) common: ToHostWorkRbDescCommon,
    pub(crate) msn: u32,
    pub(crate) value: u32,
    pub(crate) lost_psn: Range<u32>,
}

#[derive(Debug, Clone)]
pub(crate) enum Pmtu {
    Mtu256 = 1,
    Mtu512 = 2,
    Mtu1024 = 3,
    Mtu2048 = 4,
    Mtu4096 = 5,
}

#[derive(Debug, Clone)]
pub(crate) enum QpType {
    Rc = 2,
    Uc = 3,
    Ud = 4,
    RawPacket = 8,
    XrcSend = 9,
    XrcRecv = 10,
}

pub(crate) struct ToCardCtrlRbDescSge {
    pub(crate) addr: u64,
    pub(crate) len: u32,
    pub(crate) key: u32,
}

pub(crate) enum ToHostWorkRbDescStatus {
    Normal = 1,
    InvAccFlag = 2,
    InvOpcode = 3,
    InvMrKey = 4,
    InvMrRegion = 5,
    Unknown = 6,
}

pub(crate) enum ToHostWorkRbDescTransType {
    Rc = 0x00,
    Uc = 0x01,
    Rd = 0x02,
    Ud = 0x03,
    Cnp = 0x04,
    Xrc = 0x05,
}
