#![allow(unused)]

use num_enum::TryFromPrimitive;
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
    Read(ToCardWorkRbDescRead),
    Write(ToCardWorkRbDescWrite),
    WriteWithImm(ToCardWorkRbDescWriteWithImm),
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

pub(crate) struct ToCardWorkRbDescRead {
    pub(crate) common: ToCardWorkRbDescCommon,
    pub(crate) sge: ToCardCtrlRbDescSge,
}

pub(crate) struct ToCardWorkRbDescWrite {
    pub(crate) common: ToCardWorkRbDescCommon,
    pub(crate) is_last: bool,
    pub(crate) is_first: bool,
    pub(crate) sge0: ToCardCtrlRbDescSge,
    pub(crate) sge1: Option<ToCardCtrlRbDescSge>,
    pub(crate) sge2: Option<ToCardCtrlRbDescSge>,
    pub(crate) sge3: Option<ToCardCtrlRbDescSge>,
}

pub(crate) struct ToCardWorkRbDescWriteWithImm {
    pub(crate) common: ToCardWorkRbDescCommon,
    pub(crate) is_last: bool,
    pub(crate) is_first: bool,
    pub(crate) imm: [u8; 4],
    pub(crate) sge0: ToCardCtrlRbDescSge,
    pub(crate) sge1: Option<ToCardCtrlRbDescSge>,
    pub(crate) sge2: Option<ToCardCtrlRbDescSge>,
    pub(crate) sge3: Option<ToCardCtrlRbDescSge>,
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

#[derive(TryFromPrimitive)]
#[repr(u8)]
enum CtrlRbDescOpcode {
    UpdateMrTable = 0x00,
    UpdatePageTable = 0x01,
    QpManagement = 0x02,
}

enum ToCardWorkRbDescOpcode {
    // IBV_WR_RDMA_WRITE           =  0,
    // IBV_WR_RDMA_WRITE_WITH_IMM  =  1,
    // IBV_WR_SEND                 =  2,
    // IBV_WR_SEND_WITH_IMM        =  3,
    // IBV_WR_RDMA_READ            =  4,
    // IBV_WR_ATOMIC_CMP_AND_SWP   =  5,
    // IBV_WR_ATOMIC_FETCH_AND_ADD =  6,
    // IBV_WR_LOCAL_INV            =  7,
    // IBV_WR_BIND_MW              =  8,
    // IBV_WR_SEND_WITH_INV        =  9,
    // IBV_WR_TSO                  = 10,
    // IBV_WR_DRIVER1              = 11,
    // IBV_WR_RDMA_READ_RESP       = 12, // Not defined in rdma-core
    // IBV_WR_FLUSH                = 14,
    // IBV_WR_ATOMIC_WRITE         = 15
    Write = 0,
    WriteWithImm = 1,
    Read = 4,
}

impl ToCardCtrlRbDesc {
    pub(super) fn write(&self, dst: &mut [u8]) {
        fn write_common_header(dst: &mut [u8], opcode: CtrlRbDescOpcode, op_id: [u8; 4]) {
            // typedef struct {
            //     Bit#(32)                userData;
            //     ReservedZero#(20)       reserved1;
            //     Bit#(4)                 extraSegmentCnt;
            //     Bit#(6)                 opCode;
            //     Bool                    isSuccessOrNeedSignalCplt;
            //     Bool                    valid;
            // } CmdQueueDescCommonHead deriving(Bits, FShow);

            let valid = (true as u8) << 7;
            let is_success_or_need_signal_cplt = (false as u8) << 6;
            let opcode = opcode as u8;
            dst[0] = valid | is_success_or_need_signal_cplt | opcode;

            let extra_segment_cnt = 0 << 4;
            dst[1] = extra_segment_cnt;

            dst[2] = 0; // reserved1
            dst[3] = 0; // reserved1

            dst[4..8].copy_from_slice(&op_id);
        }

        fn write_update_mr_table(dst: &mut [u8], desc: &ToCardCtrlRbDescUpdateMrTable) {
            // typedef struct {
            //     ReservedZero#(7)            reserved1;
            //     Bit#(17)                    pgtOffset;
            //     Bit#(8)                     accFlags;
            //     Bit#(32)                    pdHandler;
            //     Bit#(32)                    mrKey;
            //     Bit#(32)                    mrLength;
            //     Bit#(64)                    mrBaseVA;
            //     CmdQueueDescCommonHead      commonHeader;
            // } CmdQueueReqDescUpdateMrTable deriving(Bits, FShow);

            // bits 0-7 are header bits

            dst[8..16].copy_from_slice(&desc.addr.to_le_bytes());
            dst[16..20].copy_from_slice(&desc.len.to_le_bytes());
            dst[20..24].copy_from_slice(&desc.key.to_le_bytes());
            dst[24..28].copy_from_slice(&desc.pd_hdl.to_le_bytes());
            dst[28] = desc.acc_flags;

            let pgt_offset = desc.pgt_offset.to_le_bytes();
            dst[29] = pgt_offset[0];
            dst[30] = pgt_offset[1];
            dst[31] = pgt_offset[2] << 7; // reserved1 and last bit of pgt_offset
        }

        fn write_update_page_table(dst: &mut [u8], desc: &ToCardCtrlRbDescUpdatePageTable) {
            // typedef struct {
            //     ReservedZero#(64)               reserved1;
            //     Bit#(32)                        dmaReadLength;
            //     Bit#(32)                        startIndex;
            //     Bit#(64)                        dmaAddr;
            //     CmdQueueDescCommonHead          commonHeader;
            // } CmdQueueReqDescUpdatePGT deriving(Bits, FShow);

            // bits 0-7 are header bits

            dst[8..16].copy_from_slice(&desc.start_addr.to_le_bytes());
            dst[16..20].copy_from_slice(&(desc.pgt_idx * 8).to_le_bytes());
            dst[20..24].copy_from_slice(&(desc.pgte_cnt * 8).to_le_bytes());
            dst[24..32].copy_from_slice(&[0; 8]);
        }

        fn write_qp_management(dst: &mut [u8], desc: &ToCardCtrlRbDescQpManagement) {
            // typedef struct {
            //     ReservedZero#(104)              reserved1;      // 104 bits
            //     ReservedZero#(5)                reserved2;      // 5   bits
            //     PMTU                            pmtu;           // 3   bits
            //     FlagsType#(MemAccessTypeFlag)   rqAccessFlags;  // 8   bits
            //     ReservedZero#(4)                reserved3;      // 4   bits
            //     TypeQP                          qpType;         // 4   bits
            //     HandlerPD                       pdHandler;      // 32  bits
            //     QPN                             qpn;            // 24  bits
            //     ReservedZero#(6)                reserved4;      // 6   bits
            //     Bool                            isError;        // 1   bit
            //     Bool                            isValid;        // 1   bit
            //     CmdQueueDescCommonHead          commonHeader;   // 64  bits
            // } CmdQueueReqDescQpManagementSeg0 deriving(Bits, FShow);

            // bits 0-7 are header bits

            let is_valid = (desc.is_valid as u8) << 7;
            let is_error = (false as u8) << 6;
            dst[8] = is_valid | is_error; // and reserved4

            let qpn = desc.qpn.to_le_bytes();
            dst[9..12].copy_from_slice(&qpn[0..3]);

            dst[12..16].copy_from_slice(&desc.pd_hdl.to_le_bytes());

            dst[16] = (desc.qp_type.clone() as u8) << 4; // and reserved3

            dst[17] = desc.rq_acc_flags;

            dst[18] = (desc.pmtu.clone() as u8) << 3; // and reserved2

            dst[19..32].copy_from_slice(&[0; 13]); // reserved1
        }

        match self {
            ToCardCtrlRbDesc::UpdateMrTable(desc) => {
                write_common_header(dst, CtrlRbDescOpcode::UpdateMrTable, desc.common.op_id);
                write_update_mr_table(dst, desc);
            }
            ToCardCtrlRbDesc::UpdatePageTable(desc) => {
                write_common_header(dst, CtrlRbDescOpcode::UpdatePageTable, desc.common.op_id);
                write_update_page_table(dst, desc);
            }
            ToCardCtrlRbDesc::QpManagement(desc) => {
                write_common_header(dst, CtrlRbDescOpcode::QpManagement, desc.common.op_id);
                write_qp_management(dst, desc);
            }
        }
    }

    pub(super) fn serialized_desc_cnt(&self) -> usize {
        1
    }
}

impl ToHostCtrlRbDesc {
    pub(super) fn read(src: &[u8]) -> ToHostCtrlRbDesc {
        // typedef struct {
        //     Bit#(32)                userData;
        //     ReservedZero#(20)       reserved1;
        //     Bit#(4)                 extraSegmentCnt;
        //     Bit#(6)                 opCode;
        //     Bool                    isSuccessOrNeedSignalCplt;
        //     Bool                    valid;
        // } CmdQueueDescCommonHead deriving(Bits, FShow);

        let valid = (src[0] >> 7) != 0;
        assert!(valid);

        let extra_segment_cnt = src[1] >> 4;
        assert!(extra_segment_cnt == 0);

        let is_success = (src[0] >> 6) != 0;
        let opcode = CtrlRbDescOpcode::try_from(src[0] & 0b00111111).unwrap();
        let op_id = src[4..8].try_into().unwrap();

        let common = ToHostCtrlRbDescCommon { op_id, is_success };

        match opcode {
            CtrlRbDescOpcode::UpdateMrTable => {
                ToHostCtrlRbDesc::UpdateMrTable(ToHostCtrlRbDescUpdateMrTable { common })
            }
            CtrlRbDescOpcode::UpdatePageTable => {
                ToHostCtrlRbDesc::UpdatePageTable(ToHostCtrlRbDescUpdatePageTable { common })
            }
            CtrlRbDescOpcode::QpManagement => {
                ToHostCtrlRbDesc::QpManagement(ToHostCtrlRbDescQpManagement { common })
            }
        }
    }

    pub(super) fn serialized_desc_cnt(&self) -> usize {
        1
    }
}

impl ToCardWorkRbDesc {
    pub(super) fn write_0(&self, dst: &mut [u8]) {
        let (common, opcode, is_first, is_last) = match self {
            ToCardWorkRbDesc::Read(desc) => {
                (&desc.common, ToCardWorkRbDescOpcode::Read, false, false)
            }
            ToCardWorkRbDesc::Write(desc) => (
                &desc.common,
                ToCardWorkRbDescOpcode::Write,
                desc.is_first,
                desc.is_last,
            ),
            ToCardWorkRbDesc::WriteWithImm(desc) => (
                &desc.common,
                ToCardWorkRbDescOpcode::WriteWithImm,
                desc.is_first,
                desc.is_last,
            ),
        };

        // typedef struct {
        //     Length                  totalLen;                       // 32 bits
        //     ReservedZero#(20)       reserved1;                      // 20 bits
        //     Bit#(4)                 extraSegmentCnt;                //  4 bits
        //     WorkReqOpCode           opCode;                         //  4 bits
        //     Bool                    isLast;                         //  1 bits
        //     Bool                    isFirst;                        //  1 bits
        //     Bool                    isSuccessOrNeedSignalCplt;      //  1 bits
        //     Bool                    valid;                          //  1 bit
        // } SendQueueDescCommonHead deriving(Bits, FShow);

        let valid = (true as u8) << 7;
        let is_success_or_need_signal_cplt = (false as u8) << 6;
        let is_first = (is_first as u8) << 5;
        let is_last = (is_last as u8) << 4;
        let opcode = opcode as u8;

        dst[0] = valid | is_success_or_need_signal_cplt | is_first | is_last | opcode;

        let extra_segment_cnt = self.serialized_desc_cnt() - 1;
        dst[1] = (extra_segment_cnt as u8) << 4; // extraSegmentCnt and reserved1

        dst[2..4].copy_from_slice(&[0; 2]); // reserved1

        dst[4..8].copy_from_slice(&common.total_len.to_le_bytes());

        // typedef struct {
        //     ReservedZero#(64)           reserved1;        // 64 bits
        //     AddrIPv4                    dqpIP;            // 32 bits
        //     RKEY                        rkey;             // 32 bits
        //     ADDR                        raddr;            // 64 bits
        //     SendQueueDescCommonHead     commonHeader;     // 64 bits
        // } SendQueueReqDescSeg0 deriving(Bits, FShow);

        dst[8..16].copy_from_slice(&common.raddr.to_le_bytes());
        dst[16..20].copy_from_slice(&common.rkey.to_le_bytes());
        dst[20..24].copy_from_slice(&common.dqp_ip.octets());
        dst[24..32].copy_from_slice(&[0; 8]); // reserved1
    }

    fn write_1(&self, dst: &mut [u8]) {
        // typedef struct {
        //     ReservedZero#(64)       reserved1;          // 64 bits

        //     IMM                     imm;                // 32 bits

        //     ReservedZero#(8)        reserved2;          // 8  bits
        //     QPN                     dqpn;               // 24 bits

        //     ReservedZero#(16)       reserved3;          // 16 bits
        //     MAC                     macAddr;            // 48 bits

        //     ReservedZero#(8)        reserved4;          // 8  bits
        //     PSN                     psn;                // 24 bits

        //     ReservedZero#(5)        reserved5;          // 5  bits
        //     NumSGE                  sgeCnt;             // 3  bits

        //     ReservedZero#(4)        reserved6;          // 4  bits
        //     TypeQP                  qpType;             // 4  bits

        //     ReservedZero#(3)        reserved7;          // 3  bits
        //     WorkReqSendFlag         flags;              // 5  bits

        //     ReservedZero#(5)        reserved8;          // 5  bits
        //     PMTU                    pmtu;               // 3  bits
        // } SendQueueReqDescSeg1 deriving(Bits, FShow);

        let (common, sge_cnt) = match self {
            ToCardWorkRbDesc::Read(desc) => (&desc.common, 1),
            ToCardWorkRbDesc::Write(desc) => (
                &desc.common,
                1 + desc.sge1.is_some() as u8
                    + desc.sge2.is_some() as u8
                    + desc.sge3.is_some() as u8,
            ),
            ToCardWorkRbDesc::WriteWithImm(desc) => (
                &desc.common,
                1 + desc.sge1.is_some() as u8
                    + desc.sge2.is_some() as u8
                    + desc.sge3.is_some() as u8,
            ),
        };

        dst[0] = (common.pmtu.clone() as u8) << 5; // and reserved8
        dst[1] = (common.flags as u8) << 3; // and reserved7
        dst[2] = (common.qp_type.clone() as u8) << 4; // and reserved6
        dst[3] = sge_cnt << 5; // and reserved5

        dst[4..7].copy_from_slice(&common.psn.to_le_bytes()[0..3]);
        dst[7] = 0; // reserved4

        dst[8..14].copy_from_slice(&common.mac_addr);
        dst[14..16].copy_from_slice(&[0; 2]); // reserved3

        dst[16..20].copy_from_slice(&common.dqpn.to_le_bytes()[0..3]);
        dst[20] = 0; // reserved2

        if let ToCardWorkRbDesc::WriteWithImm(desc) = self {
            dst[24..28].copy_from_slice(&desc.imm);
        } else {
            dst[24..28].copy_from_slice(&[0; 4]);
        }

        dst[28..32].copy_from_slice(&[0; 4]); // reserved1
    }

    fn write_2(&self, dst: &mut [u8]) {
        // typedef struct {
        //     ADDR   laddr;         // 64 bits
        //     Length len;           // 32 bits
        //     LKEY   lkey;          // 32 bits
        // } SendQueueReqDescFragSGE deriving(Bits, FShow);

        // typedef struct {
        //     SendQueueReqDescFragSGE     sge1;       // 128 bits
        //     SendQueueReqDescFragSGE     sge2;       // 128 bits
        // } SendQueueReqDescVariableLenSGE deriving(Bits, FShow);

        let (sge0, sge1) = match self {
            ToCardWorkRbDesc::Read(desc) => (&desc.sge, None),
            ToCardWorkRbDesc::Write(desc) => (&desc.sge0, desc.sge1.as_ref()),
            ToCardWorkRbDesc::WriteWithImm(desc) => (&desc.sge0, desc.sge1.as_ref()),
        };

        dst[0..4].copy_from_slice(&sge0.key.to_le_bytes());
        dst[4..8].copy_from_slice(&sge0.len.to_le_bytes());
        dst[8..16].copy_from_slice(&sge0.addr.to_le_bytes());

        if let Some(sge1) = sge1 {
            dst[16..20].copy_from_slice(&sge1.key.to_le_bytes());
            dst[20..24].copy_from_slice(&sge1.len.to_le_bytes());
            dst[24..32].copy_from_slice(&sge1.addr.to_le_bytes());
        } else {
            dst[16..32].copy_from_slice(&[0; 16]);
        }
    }

    fn write_3(&self, dst: &mut [u8]) {
        // typedef struct {
        //     ADDR   laddr;         // 64 bits
        //     Length len;           // 32 bits
        //     LKEY   lkey;          // 32 bits
        // } SendQueueReqDescFragSGE deriving(Bits, FShow);

        // typedef struct {
        //     SendQueueReqDescFragSGE     sge1;       // 128 bits
        //     SendQueueReqDescFragSGE     sge2;       // 128 bits
        // } SendQueueReqDescVariableLenSGE deriving(Bits, FShow);

        let (sge2, sge3) = match self {
            ToCardWorkRbDesc::Read(desc) => (None, None),
            ToCardWorkRbDesc::Write(desc) => (desc.sge2.as_ref(), desc.sge3.as_ref()),
            ToCardWorkRbDesc::WriteWithImm(desc) => (desc.sge2.as_ref(), desc.sge3.as_ref()),
        };

        if let Some(sge2) = sge2 {
            dst[16..20].copy_from_slice(&sge2.key.to_le_bytes());
            dst[20..24].copy_from_slice(&sge2.len.to_le_bytes());
            dst[24..32].copy_from_slice(&sge2.addr.to_le_bytes());
        } else {
            dst[16..32].copy_from_slice(&[0; 16]);
        }

        if let Some(sge3) = sge3 {
            dst[16..20].copy_from_slice(&sge3.key.to_le_bytes());
            dst[20..24].copy_from_slice(&sge3.len.to_le_bytes());
            dst[24..32].copy_from_slice(&sge3.addr.to_le_bytes());
        } else {
            dst[16..32].copy_from_slice(&[0; 16]);
        }
    }

    pub(super) fn serialized_desc_cnt(&self) -> usize {
        let sge_desc_cnt = match self {
            ToCardWorkRbDesc::Read(_) => 1,
            ToCardWorkRbDesc::Write(desc) => 1 + desc.sge2.is_some() as usize,
            ToCardWorkRbDesc::WriteWithImm(desc) => 1 + desc.sge2.is_some() as usize,
        };

        2 + sge_desc_cnt
    }
}
