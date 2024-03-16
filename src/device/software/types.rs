use crate::{
    device::{
        MemAccessTypeFlag, ToCardCtrlRbDescSge, ToCardWorkRbDescCommon, ToCardWorkRbDescOpcode,
        ToHostWorkRbDescAethCode,
        ToHostWorkRbDescOpcode, ToHostWorkRbDescTransType,
    },
    ToCardWorkRbDesc,
};

use super::packet::{Immediate, PacketError, AETH, BTH, RDMA_PAYLOAD_ALIGNMENT, RETH};

/// Queue-pair number
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct Qpn(u32);

impl Qpn {
    pub fn new(qpn: u32) -> Self {
        Qpn(qpn)
    }

    pub fn get(&self) -> u32 {
        self.0
    }
}

/// Packet Sequence Number
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Psn(u32);

impl Psn {
    pub fn new(psn: u32) -> Self {
        Psn(psn)
    }

    pub fn get(&self) -> u32 {
        self.0
    }
}

/// Protection Domain handle
#[derive(Debug, Clone, Copy)]
pub(crate) struct PDHandle(u32);

impl PDHandle {
    pub fn new(handle: u32) -> Self {
        PDHandle(handle)
    }

    #[cfg(test)]
    pub fn get(&self) -> u32 {
        self.0
    }
}

/// The general key type, like RKey, Lkey
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub(crate) struct Key([u8; 4]);

impl Key {
    pub fn new(key: [u8; 4]) -> Self {
        Key(key)
    }

    pub fn get(&self) -> [u8; 4] {
        self.0
    }
}

/// Partition Key
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct PKey(u16);
impl PKey {
    pub fn new(key: u16) -> Self {
        Self(key)
    }

    pub fn get(&self) -> u16 {
        self.0
    }
}

/// State of the queue pair
#[allow(dead_code)]
pub enum StateQP {
    Reset,
    Init,
    Rtr,
    Rts,
    Sqd,
    Sqe,
    Err,
    Unknown,
    Create, // Not defined in rdma-core
}

/// A abstraction of a RDMA message.
#[derive(Debug, Clone)]
pub enum Metadata {
    /// RDMA write, read request and response
    General(RdmaGeneralMeta),

    /// Acknowledge message
    Acknowledge(AethHeader),
}

impl Metadata {
    pub fn get_opcode(&self) -> ToHostWorkRbDescOpcode {
        match self {
            Metadata::General(header) => header.common_meta.opcode.clone(),
            Metadata::Acknowledge(header) => header.common_meta.opcode.clone(),
        }
    }

    pub fn common_meta(&self) -> &RdmaMessageMetaCommon {
        match self {
            Metadata::General(header) => &header.common_meta,
            Metadata::Acknowledge(header) => &header.common_meta,
        }
    }
}

/// A scatter-gather list element.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SGListElement {
    pub data: *const u8,
    pub len: usize,
}

/// A payload info, which contains the scatter-gather list and the total length of the payload.
#[derive(Debug, Clone)]
pub(crate) struct PayloadInfo {
    sg_list: Vec<SGListElement>,
    total_len: usize,
}

impl PayloadInfo {
    pub fn new() -> Self {
        PayloadInfo {
            sg_list: Vec::new(),
            total_len: 0,
        }
    }

    pub fn new_with_data(data: *const u8, len: usize) -> Self {
        PayloadInfo {
            sg_list: vec![SGListElement { data, len }],
            total_len: len,
        }
    }

    pub fn get_length(&self) -> usize {
        self.total_len
    }

    pub fn get_pad_cnt(&self) -> usize {
        let mut pad_cnt = (RDMA_PAYLOAD_ALIGNMENT - self.total_len % RDMA_PAYLOAD_ALIGNMENT) as u8;
        if pad_cnt as usize == RDMA_PAYLOAD_ALIGNMENT {
            pad_cnt = 0
        }
        pad_cnt as usize
    }

    pub fn with_pad_length(&self) -> usize {
        self.total_len + self.get_pad_cnt()
    }

    pub fn add(&mut self, data: *const u8, len: usize) {
        self.sg_list.push(SGListElement { data, len });
        self.total_len += len;
    }

    #[cfg(test)]
    pub fn get_sg_list(&self) -> &Vec<SGListElement> {
        &self.sg_list
    }

    pub fn copy_to(&self, mut dst: *mut u8) {
        for i in 0..self.sg_list.len() {
            unsafe {
                std::ptr::copy_nonoverlapping(self.sg_list[i].data, dst, self.sg_list[i].len);
                dst = dst.add(self.sg_list[i].len);
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct RdmaMessage {
    pub meta_data: Metadata,
    pub payload: PayloadInfo,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RethHeader {
    pub va: u64,
    pub rkey: Key,
    pub len: u32,
}

impl From<&RETH> for RethHeader {
    fn from(reth: &RETH) -> Self {
        RethHeader {
            va: reth.get_va(),
            rkey: Key::new(reth.get_rkey()),
            len: reth.get_dlen(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RdmaMessageMetaCommon {
    pub tran_type: ToHostWorkRbDescTransType,
    pub opcode: ToHostWorkRbDescOpcode,
    pub solicited: bool,
    pub pkey: PKey,
    pub dqpn: Qpn,
    pub ack_req: bool,
    pub psn: Psn,
}

impl TryFrom<&BTH> for RdmaMessageMetaCommon {
    type Error = PacketError;
    fn try_from(bth: &BTH) -> Result<Self, PacketError> {
        Ok(Self {
            tran_type: ToHostWorkRbDescTransType::try_from(bth.get_transaction_type())?,
            opcode: ToHostWorkRbDescOpcode::try_from(bth.get_opcode())?,
            solicited: bth.get_solicited(),
            pkey: PKey::new(bth.get_pkey()),
            dqpn: Qpn(bth.get_destination_qpn()),
            ack_req: bth.get_ack_req(),
            psn: Psn(bth.get_psn()),
        })
    }
}

#[derive(Debug, Clone)]
pub struct RdmaGeneralMeta {
    pub common_meta: RdmaMessageMetaCommon,
    pub reth: RethHeader,
    pub imm: Option<[u8; 4]>,
    pub secondary_reth: Option<RethHeader>,
}

impl RdmaGeneralMeta {
    pub fn new_from_packet(
        bth: &BTH,
        reth: &RETH,
        imm: Option<&Immediate>,
        secondary_reth: Option<&RETH>,
    ) -> Result<Self, PacketError> {
        Ok(RdmaGeneralMeta {
            common_meta: RdmaMessageMetaCommon::try_from(bth)?,
            reth: RethHeader::from(reth),
            imm: imm.map(|imm| imm.get_immediate()),
            secondary_reth: secondary_reth.map(RethHeader::from),
        })
    }

    pub fn is_read_request(&self) -> bool {
        matches!(
            self.common_meta.opcode,
            ToHostWorkRbDescOpcode::RdmaReadRequest
        )
    }

    pub fn has_payload(&self) -> bool {
        matches!(
            self.common_meta.opcode,
            ToHostWorkRbDescOpcode::RdmaWriteFirst
                | ToHostWorkRbDescOpcode::RdmaWriteMiddle
                | ToHostWorkRbDescOpcode::RdmaWriteLast
                | ToHostWorkRbDescOpcode::RdmaWriteLastWithImmediate
                | ToHostWorkRbDescOpcode::RdmaWriteOnly
                | ToHostWorkRbDescOpcode::RdmaWriteOnlyWithImmediate
                | ToHostWorkRbDescOpcode::RdmaReadResponseFirst
                | ToHostWorkRbDescOpcode::RdmaReadResponseMiddle
                | ToHostWorkRbDescOpcode::RdmaReadResponseLast
                | ToHostWorkRbDescOpcode::RdmaReadResponseOnly
        )
    }

    pub fn needed_permissions(&self) -> MemAccessTypeFlag {
        if self.has_payload() {
            return MemAccessTypeFlag::IbvAccessRemoteWrite;
        } else if self.is_read_request() {
            return MemAccessTypeFlag::IbvAccessRemoteRead;
        }
        MemAccessTypeFlag::IbvAccessNoFlags
    }
}
#[derive(Debug, Clone)]
pub struct AethHeader {
    pub common_meta: RdmaMessageMetaCommon,
    pub aeth_code: ToHostWorkRbDescAethCode,
    pub aeth_value: u8,
    pub msn: u32,
}

impl AethHeader {
    pub fn new_from_packet(bth: &BTH, aeth: &AETH) -> Result<Self, PacketError> {
        let aeth_code = ToHostWorkRbDescAethCode::try_from(aeth.get_aeth_code())?;
        let aeth_value = aeth.get_aeth_value();
        let msn = aeth.get_msn();

        Ok(AethHeader {
            common_meta: RdmaMessageMetaCommon::try_from(bth)?,
            aeth_code,
            aeth_value,
            msn,
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct SGListElementWithKey {
    pub(crate) addr: u64,
    pub(crate) len: u32,
    pub(crate) key: Key,
}

impl Default for SGListElementWithKey {
    fn default() -> Self {
        SGListElementWithKey {
            addr: 0,
            len: 0,
            key: Key::new([0; 4]),
        }
    }
}

impl From<ToCardCtrlRbDescSge> for SGListElementWithKey {
    fn from(sge: ToCardCtrlRbDescSge) -> Self {
        SGListElementWithKey {
            addr: sge.addr,
            len: sge.len,
            key: Key::new(sge.key.to_be_bytes()),
        }
    }
}
pub struct SGList {
    pub data: [SGListElementWithKey; 4],
    pub cur_level: u32,
    pub len: u32,
}

impl SGList {
    #[allow(dead_code)]
    pub fn new() -> Self {
        SGList {
            data: [SGListElementWithKey::default(); 4],
            cur_level: 0,
            len: 0,
        }
    }

    pub fn new_with_sge(sge: ToCardCtrlRbDescSge) -> Self {
        SGList {
            data: [
                SGListElementWithKey::from(sge),
                SGListElementWithKey::default(),
                SGListElementWithKey::default(),
                SGListElementWithKey::default(),
            ],
            cur_level: 0,
            len: 1,
        }
    }

    fn get_sge_from_option(sge: Option<ToCardCtrlRbDescSge>) -> (SGListElementWithKey, u32) {
        match sge {
            Some(sge) => (SGListElementWithKey::from(sge), 1),
            None => (SGListElementWithKey::default(), 0),
        }
    }

    pub fn new_with_sge_list(
        sge0: ToCardCtrlRbDescSge,
        sge1: Option<ToCardCtrlRbDescSge>,
        sge2: Option<ToCardCtrlRbDescSge>,
        sge3: Option<ToCardCtrlRbDescSge>,
    ) -> Self {
        let sge0 = SGListElementWithKey::from(sge0);
        let mut counter = 1;
        let (sge1, i) = Self::get_sge_from_option(sge1);
        counter += i;
        let (sge2, i) = Self::get_sge_from_option(sge2);
        counter += i;
        let (sge3, i) = Self::get_sge_from_option(sge3);
        counter += i;
        SGList {
            data: [sge0, sge1, sge2, sge3],
            cur_level: 0,
            len: counter,
        }
    }

    #[cfg(test)]
    pub fn into_four_sges(
        self,
    ) -> (
        ToCardCtrlRbDescSge,
        Option<ToCardCtrlRbDescSge>,
        Option<ToCardCtrlRbDescSge>,
        Option<ToCardCtrlRbDescSge>,
    ) {
        let sge1 = if self.len > 1 {
            Some(ToCardCtrlRbDescSge {
                addr: self.data[1].addr,
                len: self.data[1].len,
                key: u32::from_be_bytes(self.data[1].key.get()),
            })
        } else {
            None
        };

        let sge2 = if self.len > 2 {
            Some(ToCardCtrlRbDescSge {
                addr: self.data[2].addr,
                len: self.data[2].len,
                key: u32::from_be_bytes(self.data[2].key.get()),
            })
        } else {
            None
        };

        let sge3 = if self.len > 3 {
            Some(ToCardCtrlRbDescSge {
                addr: self.data[3].addr,
                len: self.data[3].len,
                key: u32::from_be_bytes(self.data[3].key.get()),
            })
        } else {
            None
        };
        (
            ToCardCtrlRbDescSge {
                addr: self.data[0].addr,
                len: self.data[0].len,
                key: u32::from_be_bytes(self.data[0].key.get()),
            },
            sge1,
            sge2,
            sge3,
        )
    }
}

#[allow(dead_code)]
pub(crate) struct ToCardDescriptor {
    pub(crate) opcode: ToCardWorkRbDescOpcode,
    pub(crate) common: ToCardWorkRbDescCommon,
    pub(crate) imm: Option<[u8; 4]>,
    pub(crate) is_first: Option<bool>,
    pub(crate) is_last: Option<bool>,
    pub(crate) sg_list: SGList,
}


impl From<ToCardWorkRbDesc> for ToCardDescriptor {
    fn from(desc: ToCardWorkRbDesc) -> Self {
        match desc {
            ToCardWorkRbDesc::Write(desc) => ToCardDescriptor {
                opcode: ToCardWorkRbDescOpcode::Write,
                common: desc.common,
                is_first: Some(desc.is_first),
                is_last: Some(desc.is_last),
                imm: None,
                sg_list: SGList::new_with_sge_list(desc.sge0, desc.sge1, desc.sge2, desc.sge3),
            },
            ToCardWorkRbDesc::Read(desc) => ToCardDescriptor {
                opcode: ToCardWorkRbDescOpcode::Read,
                common: desc.common,
                is_first: None,
                is_last: None,
                imm: None,
                sg_list: SGList::new_with_sge(desc.sge),
            },
            ToCardWorkRbDesc::WriteWithImm(desc) => ToCardDescriptor {
                opcode: ToCardWorkRbDescOpcode::WriteWithImm,
                common: desc.common,
                is_first: Some(desc.is_first),
                is_last: Some(desc.is_last),
                imm: Some(desc.imm),
                sg_list: SGList::new_with_sge_list(desc.sge0, desc.sge1, desc.sge2, desc.sge3),
            },
            ToCardWorkRbDesc::ReadResp(desc) => ToCardDescriptor {
                opcode: ToCardWorkRbDescOpcode::ReadResp,
                common: desc.common,
                is_first: Some(desc.is_first),
                is_last: Some(desc.is_last),
                imm: None,
                sg_list: SGList::new_with_sge_list(desc.sge0, desc.sge1, desc.sge2, desc.sge3),
            },
        }
    }
}
