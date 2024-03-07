use crate::device::{AethCode, MemAccessTypeFlag, RdmaOpcode, TransType};

use super::packet::{Immediate, AETH, BTH, RETH, RDMA_PAYLOAD_ALIGNMENT, PacketError};

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
#[derive(Debug, Clone, PartialEq)]
pub enum Metadata {
    /// RDMA write, read request and response
    General(RdmaGeneralMeta),

    /// Acknowledge message
    Acknowledge(AethHeader),
}

impl Metadata {
    pub fn get_opcode(&self) -> RdmaOpcode {
        match self {
            Metadata::General(header) => header.common_meta.opcode,
            Metadata::Acknowledge(header) => header.common_meta.opcode,
        }
    }

    #[cfg(test)]
    pub fn get_psn(&self) -> Psn {
        match self {
            Metadata::General(header) => header.common_meta.psn,
            Metadata::Acknowledge(header) => header.common_meta.psn,
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

#[derive(Debug, Clone, PartialEq)]
pub struct RdmaMessageMetaCommon {
    pub tran_type: TransType,
    pub opcode: RdmaOpcode,
    pub solicited: bool,
    pub pkey: PKey,
    pub dqpn: Qpn,
    pub ack_req: bool,
    pub psn: Psn,
}

impl TryFrom<&BTH> for RdmaMessageMetaCommon {
    type Error = PacketError;
    fn try_from(bth: &BTH) -> Result<Self,PacketError> {
        Ok(Self {
            tran_type: TransType::try_from(bth.get_transaction_type())?,
            opcode: RdmaOpcode::try_from(bth.get_opcode())?,
            solicited: bth.get_solicited(),
            pkey: PKey::new(bth.get_pkey()),
            dqpn: Qpn(bth.get_destination_qpn()),
            ack_req: bth.get_ack_req(),
            psn: Psn(bth.get_psn()),
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
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
    ) -> Result<Self,PacketError> {
        Ok(RdmaGeneralMeta {
            common_meta: RdmaMessageMetaCommon::try_from(bth)?,
            reth: RethHeader::from(reth),
            imm: imm.map(|imm| imm.get_immediate()),
            secondary_reth: secondary_reth.map(RethHeader::from),
        })
    }

    pub fn is_read_request(&self) -> bool {
        matches!(self.common_meta.opcode, RdmaOpcode::RdmaReadRequest)
    }

    pub fn has_payload(&self) -> bool {
        matches!(self.common_meta.opcode, RdmaOpcode::RdmaWriteFirst
            | RdmaOpcode::RdmaWriteMiddle
            | RdmaOpcode::RdmaWriteLast
            | RdmaOpcode::RdmaWriteLastWithImmediate
            | RdmaOpcode::RdmaWriteOnly
            | RdmaOpcode::RdmaWriteOnlyWithImmediate
            | RdmaOpcode::RdmaReadResponseFirst
            | RdmaOpcode::RdmaReadResponseMiddle
            | RdmaOpcode::RdmaReadResponseLast
            | RdmaOpcode::RdmaReadResponseOnly)
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
#[derive(Debug, Clone, PartialEq)]
pub struct AethHeader {
    pub common_meta: RdmaMessageMetaCommon,
    pub aeth_code: AethCode,
    pub aeth_value: u8,
    pub msn: u32,
}

impl AethHeader {
    pub fn new_from_packet(bth: &BTH, aeth: &AETH) -> Result<Self,PacketError> {
        let aeth_code = AethCode::try_from(aeth.get_aeth_code())?;
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
