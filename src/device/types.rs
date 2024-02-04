#![allow(unused)]

/// A descriptor for the to-card control ring buffer.
pub(crate) enum ToCardCtrlRbDesc {
    UpdateMrTable(ToCardCtrlRbDescUpdateMrTable),
    UpdatePageTable(ToCardCtrlRbDescUpdatePageTable),
    QpManagement(ToCardCtrlRbDescQpManagement),
}

/// A descriptor for the to-host control ring buffer.
pub(crate) enum ToHostCtrlRbDesc {
    UpdateMrTable(ToHostCtrlRbDescUpdateMrTable),
    UpdatePageTable(ToHostCtrlRbDescUpdatePageTable),
    QpManagement(ToHostCtrlRbDescQpManagement),
}

/// A descriptor for the to-card work ring buffer.
pub(crate) struct ToCardWorkRbDesc {}

/// A descriptor for the to-host work ring buffer.
pub(crate) enum ToHostWorkRbDesc {}

pub(crate) struct ToCardCtrlRbDescUpdateMrTable {
    common_header: CtrlRbDescCommonHeader,
    base_va: u64,
    mr_length: u32,
    mr_key: u32,
    pd_handler: u32,
    acc_flags: u8,
    pgt_offset: u32,
}

pub(crate) struct ToCardCtrlRbDescUpdatePageTable {
    common_header: CtrlRbDescCommonHeader,
    dma_addr: u64,
    start_index: u32,
    dma_read_length: u32,
}

pub(crate) struct ToCardCtrlRbDescQpManagement {
    common_header: CtrlRbDescCommonHeader,
    is_valid: bool,
    is_error: bool,
    qpn: u32,
    pd_handler: u32,
    qp_type: QpType,
    rq_access_flags: MemAccessTypeFlag,
    pmtu: Pmtu,
}

pub(crate) struct ToHostCtrlRbDescUpdateMrTable {
    common_header: CtrlRbDescCommonHeader,
}

pub(crate) struct ToHostCtrlRbDescUpdatePageTable {
    common_header: CtrlRbDescCommonHeader,
}

pub(crate) struct ToHostCtrlRbDescQpManagement {
    common_header: CtrlRbDescCommonHeader,
    is_valid: bool,
    is_error: bool,
    qpn: u32,
    pd_handler: u32,
    qp_type: QpType,
    rq_access_flags: MemAccessTypeFlag,
    pmtu: Pmtu,
}

pub(crate) struct CtrlRbDescCommonHeader {
    valid: bool,
    opcode: CtrlRbDescOpcode,
    extra_segment_cnt: u8,
    is_success_or_need_signal_cplt: bool,
    user_data: [u8; 4],
}

pub(crate) enum CtrlRbDescOpcode {
    UpdateMrTable = 0x00,
    UpdatePageTable = 0x01,
    QpManagement = 0x02,
}

pub(crate) enum QpType {
    Rc = 2,
    Uc = 3,
    Ud = 4,
    RawPacket = 8,
    XrcSend = 9,
    XrcRecv = 10,
}

pub(crate) enum MemAccessTypeFlag {
    NoFlags = 0,
    LocalWrite = 1,
    RemoteWrite = 2,
    RemoteRead = 4,
    RemoteAtomic = 8,
    MwBind = 16,
    ZeroBased = 32,
    OnDemand = 64,
    HugeTlb = 128,
}

pub(crate) enum Pmtu {
    Mtu256 = 1,
    Mtu512 = 2,
    Mtu1024 = 3,
    Mtu2048 = 4,
    Mtu4096 = 5,
}
