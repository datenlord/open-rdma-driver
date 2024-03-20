#![allow(unused)]

use bitfield::bitfield;
use bitflags::bitflags;
use eui48::MacAddress;
use num_enum::TryFromPrimitive;
use std::{
    mem::{size_of, size_of_val},
    net::Ipv4Addr,
    ops::Range,
};

use crate::{
    types::{Key, MemAccessTypeFlag, Msn, Pmtu, Psn, QpType, Qpn},
    utils::u8_slice_to_u64,
    Error, Sge,
};

pub(crate) enum ToCardCtrlRbDesc {
    UpdateMrTable(ToCardCtrlRbDescUpdateMrTable),
    UpdatePageTable(ToCardCtrlRbDescUpdatePageTable),
    QpManagement(ToCardCtrlRbDescQpManagement),
    SetNetworkParam(ToCardCtrlRbDescSetNetworkParam),
    SetRawPacketReceiveMeta(ToCardCtrlRbDescSetRawPacketReceiveMeta),
}

pub(crate) enum ToHostCtrlRbDesc {
    UpdateMrTable(ToHostCtrlRbDescUpdateMrTable),
    UpdatePageTable(ToHostCtrlRbDescUpdatePageTable),
    QpManagement(ToHostCtrlRbDescQpManagement),
    SetNetworkParam(ToHostCtrlRbDescSetNetworkParam),
    SetRawPacketReceiveMeta(ToHostCtrlRbDescSetRawPacketReceiveMeta),
}

#[derive(Clone)]
#[allow(private_interfaces)]
pub enum ToCardWorkRbDesc {
    Read(ToCardWorkRbDescRead),
    Write(ToCardWorkRbDescWrite),
    WriteWithImm(ToCardWorkRbDescWriteWithImm),
    ReadResp(ToCardWorkRbDescWrite),
}

pub(crate) enum ToHostWorkRbDesc {
    Read(ToHostWorkRbDescRead),
    Write(ToHostWorkRbDescWrite),
    WriteWithImm(ToHostWorkRbDescWriteWithImm),
    Ack(ToHostWorkRbDescAck),
    Nack(ToHostWorkRbDescNack),
}

impl ToHostWorkRbDesc {
    pub(crate) fn common(&self) -> &ToHostWorkRbDescCommon {
        match self {
            ToHostWorkRbDesc::Read(desc) => &desc.common,
            ToHostWorkRbDesc::Write(desc) => &desc.common,
            ToHostWorkRbDesc::WriteWithImm(desc) => &desc.common,
            ToHostWorkRbDesc::Ack(desc) => &desc.common,
            ToHostWorkRbDesc::Nack(desc) => &desc.common,
        }
    }
}

pub(crate) struct ToCardCtrlRbDescCommon {
    pub(crate) op_id: u32, // user_data
}

pub(crate) struct ToCardCtrlRbDescUpdateMrTable {
    pub(crate) common: ToCardCtrlRbDescCommon,
    pub(crate) addr: u64,
    pub(crate) len: u32,
    pub(crate) key: Key,
    pub(crate) pd_hdl: u32,
    pub(crate) acc_flags: MemAccessTypeFlag,
    pub(crate) pgt_offset: u32,
}

pub(crate) struct ToCardCtrlRbDescUpdatePageTable {
    pub(crate) common: ToCardCtrlRbDescCommon,
    pub(crate) start_addr: u64,
    pub(crate) pgt_idx: u32,  //offset
    pub(crate) pgte_cnt: u32, //bytes
}

pub(crate) struct ToCardCtrlRbDescQpManagement {
    pub(crate) common: ToCardCtrlRbDescCommon,
    pub(crate) is_valid: bool,
    pub(crate) qpn: Qpn,
    pub(crate) pd_hdl: u32,
    pub(crate) qp_type: QpType,
    pub(crate) rq_acc_flags: MemAccessTypeFlag,
    pub(crate) pmtu: Pmtu,
}

pub(crate) struct ToCardCtrlRbDescSetNetworkParam {
    pub(crate) common: ToCardCtrlRbDescCommon,
    pub(crate) gateway: Ipv4Addr,
    pub(crate) netmask: Ipv4Addr,
    pub(crate) ipaddr: Ipv4Addr,
    pub(crate) macaddr: MacAddress,
}

pub(crate) struct ToCardCtrlRbDescSetRawPacketReceiveMeta {
    pub(crate) common: ToCardCtrlRbDescCommon,
    pub(crate) base_write_addr: u64,
    pub(crate) key: Key,
}

pub(crate) struct ToHostCtrlRbDescCommon {
    pub(crate) op_id: u32, // user_data
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

pub(crate) struct ToHostCtrlRbDescSetNetworkParam {
    pub(crate) common: ToHostCtrlRbDescCommon,
}

pub(crate) struct ToHostCtrlRbDescSetRawPacketReceiveMeta {
    pub(crate) common: ToHostCtrlRbDescCommon,
}

#[derive(Clone)]
pub(crate) struct ToCardWorkRbDescCommon {
    pub(crate) total_len: u32,
    pub(crate) raddr: u64,
    pub(crate) rkey: Key,
    pub(crate) dqp_ip: Ipv4Addr,
    pub(crate) dqpn: Qpn,
    pub(crate) mac_addr: [u8; 6],
    pub(crate) pmtu: Pmtu,
    pub(crate) flags: MemAccessTypeFlag,
    pub(crate) qp_type: QpType,
    pub(crate) psn: Psn,
}

#[derive(Clone)]
pub(crate) struct ToCardWorkRbDescRead {
    pub(crate) common: ToCardWorkRbDescCommon,
    pub(crate) sge: ToCardCtrlRbDescSge,
}

#[derive(Clone)]
pub(crate) struct ToCardWorkRbDescWrite {
    pub(crate) common: ToCardWorkRbDescCommon,
    pub(crate) is_last: bool,
    pub(crate) is_first: bool,
    pub(crate) sge0: ToCardCtrlRbDescSge,
    pub(crate) sge1: Option<ToCardCtrlRbDescSge>,
    pub(crate) sge2: Option<ToCardCtrlRbDescSge>,
    pub(crate) sge3: Option<ToCardCtrlRbDescSge>,
}

#[derive(Clone)]
pub(crate) struct ToCardWorkRbDescWriteWithImm {
    pub(crate) common: ToCardWorkRbDescCommon,
    pub(crate) is_last: bool,
    pub(crate) is_first: bool,
    pub(crate) imm: u32,
    pub(crate) sge0: ToCardCtrlRbDescSge,
    pub(crate) sge1: Option<ToCardCtrlRbDescSge>,
    pub(crate) sge2: Option<ToCardCtrlRbDescSge>,
    pub(crate) sge3: Option<ToCardCtrlRbDescSge>,
}

pub(crate) struct ToHostWorkRbDescCommon {
    pub(crate) status: ToHostWorkRbDescStatus,
    pub(crate) trans: ToHostWorkRbDescTransType,
    pub(crate) dqpn: Qpn,
    pub(crate) pad_cnt: u8,
}

pub(crate) struct ToHostWorkRbDescRead {
    pub(crate) common: ToHostWorkRbDescCommon,
    pub(crate) len: u32,
    pub(crate) laddr: u64,
    pub(crate) lkey: Key,
    pub(crate) raddr: u64,
    pub(crate) rkey: Key,
}

pub(crate) struct ToHostWorkRbDescWrite {
    pub(crate) common: ToHostWorkRbDescCommon,
    pub(crate) write_type: ToHostWorkRbDescWriteType,
    pub(crate) psn: Psn,
    pub(crate) addr: u64,
    pub(crate) len: u32,
    pub(crate) key: Key,
}

pub(crate) struct ToHostWorkRbDescWriteWithImm {
    pub(crate) common: ToHostWorkRbDescCommon,
    pub(crate) write_type: ToHostWorkRbDescWriteType,
    pub(crate) psn: Psn,
    pub(crate) imm: u32,
    pub(crate) addr: u64,
    pub(crate) len: u32,
    pub(crate) key: Key,
}

pub(crate) struct ToHostWorkRbDescAck {
    pub(crate) common: ToHostWorkRbDescCommon,
    pub(crate) msn: Msn,
    pub(crate) value: u8,
    pub(crate) psn: Psn,
}

pub(crate) struct ToHostWorkRbDescNack {
    pub(crate) common: ToHostWorkRbDescCommon,
    pub(crate) msn: Msn,
    pub(crate) value: u8,
    pub(crate) lost_psn: Range<Psn>,
}

#[derive(Debug, Clone)]
pub(crate) struct ToCardCtrlRbDescSge {
    pub(crate) addr: u64,
    pub(crate) len: u32,
    pub(crate) key: Key,
}

#[derive(TryFromPrimitive, Debug)]
#[repr(u8)]
pub(crate) enum ToHostWorkRbDescStatus {
    Normal = 1,
    InvAccFlag = 2,
    InvOpcode = 3,
    InvMrKey = 4,
    InvMrRegion = 5,
    Unknown = 6,
}

impl ToHostWorkRbDescStatus {
    pub(crate) fn is_ok(&self) -> bool {
        matches!(self, ToHostWorkRbDescStatus::Normal)
    }
}

#[derive(TryFromPrimitive, Debug, Clone)]
#[repr(u8)]
pub(crate) enum ToHostWorkRbDescTransType {
    Rc = 0x00,
    Uc = 0x01,
    Rd = 0x02,
    Ud = 0x03,
    Cnp = 0x04,
    Xrc = 0x05,
}

pub(crate) enum ToHostWorkRbDescWriteType {
    First,
    Middle,
    Last,
    Only,
}

pub(super) struct IncompleteToHostWorkRbDesc {
    parsed: ToHostWorkRbDesc,
    parsed_cnt: usize,
}

#[derive(TryFromPrimitive)]
#[repr(u8)]
enum CtrlRbDescOpcode {
    UpdateMrTable = 0x00,
    UpdatePageTable = 0x01,
    QpManagement = 0x02,
    SetNetworkParam = 0x03,
    SetRawPacketReceiveMeta = 0x04,
}

#[derive(Clone)]
pub(crate) enum ToCardWorkRbDescOpcode {
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
    ReadResp = 12, // Not defined in rdma-core
}

#[derive(TryFromPrimitive, PartialEq, Eq, Debug, Clone)]
#[repr(u8)]
pub(crate) enum ToHostWorkRbDescOpcode {
    // SendFirst = 0x00,
    // SendMiddle = 0x01,
    // SendLast = 0x02,
    // SendLastWithImmediate = 0x03,
    // SendOnly = 0x04,
    // SendOnlyWithImmediate = 0x05,
    // RdmaWriteFirst = 0x06,
    // RdmaWriteMiddle = 0x07,
    // RdmaWriteLast = 0x08,
    // RdmaWriteLastWithImmediate = 0x09,
    // RdmaWriteOnly = 0x0a,
    // RdmaWriteOnlyWithImmediate = 0x0b,
    // RdmaReadRequest = 0x0c,
    // Acknowledge = 0x11,
    // AtomicAcknowledge = 0x12,
    // CompareSwap = 0x13,
    // FetchAdd = 0x14,
    // Resync = 0x15,
    // SendLastWithInvalidate = 0x16,
    // SendOnlyWithInvalidate = 0x17,
    RdmaWriteFirst = 0x06,
    RdmaWriteMiddle = 0x07,
    RdmaWriteLast = 0x08,
    RdmaWriteLastWithImmediate = 0x09,
    RdmaWriteOnly = 0x0a,
    RdmaWriteOnlyWithImmediate = 0x0b,
    RdmaReadResponseFirst = 0x0d,
    RdmaReadResponseMiddle = 0x0e,
    RdmaReadResponseLast = 0x0f,
    RdmaReadResponseOnly = 0x10,
    RdmaReadRequest = 0x0c,
    Acknowledge = 0x11,
}

#[derive(TryFromPrimitive, Clone, PartialEq, Eq, Debug)]
#[repr(u8)]
pub(crate) enum ToHostWorkRbDescAethCode {
    // AETH_CODE_ACK  = 2'b00,
    // AETH_CODE_RNR  = 2'b01,
    // AETH_CODE_RSVD = 2'b10,
    // AETH_CODE_NAK  = 2'b11
    Ack = 0b00,
    Rnr = 0b01,
    Rsvd = 0b10,
    Nak = 0b11,
}

impl ToCardCtrlRbDesc {
    pub(super) fn write(&self, dst: &mut [u8]) {
        fn write_common_header(dst: &mut [u8], opcode: CtrlRbDescOpcode, op_id: u32) {
            // typedef struct {
            //     Bit#(32)                userData;
            //     ReservedZero#(20)       reserved1;
            //     Bit#(4)                 extraSegmentCnt;
            //     Bit#(6)                 opCode;
            //     Bool                    isSuccessOrNeedSignalCplt;
            //     Bool                    valid;
            // } CmdQueueDescCommonHead deriving(Bits, FShow);

            let mut common = CmdQueueDescCommonHead(dst);
            common.set_valid(true);
            common.set_is_success_or_need_signal_cplt(false);
            common.set_op_code(opcode as u32);
            common.set_extra_segment_cnt(0);
            common.set_user_data(op_id);
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

            // bytes 0-7 are header bytes, ignore them

            let mut update_mr_table = CmdQueueReqDescUpdateMrTable(dst);
            update_mr_table.set_mr_base_va(desc.addr);
            update_mr_table.set_mr_length(desc.len.into());
            update_mr_table.set_mr_key(desc.key.get().into());
            update_mr_table.set_pd_handler(desc.pd_hdl.into());
            update_mr_table.set_acc_flags(desc.acc_flags.bits().into());
            update_mr_table.set_pgt_offset(desc.pgt_offset.into());
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
            let mut update_pgt = CmdQueueReqDescUpdatePGT(dst);
            update_pgt.set_dma_addr(desc.start_addr);
            update_pgt.set_start_index(desc.pgt_idx.into());
            update_pgt.set_dma_read_length((desc.pgte_cnt * 8).into());
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

            // bytes[0..7] have been padding in `CmdQueueReqDescQpManagementSeg0``
            let mut seg0 = CmdQueueReqDescQpManagementSeg0(dst);
            seg0.set_is_valid(desc.is_valid);
            seg0.set_is_error(false);
            seg0.set_qpn(desc.qpn.get().into());
            seg0.set_pd_handler(desc.pd_hdl.into());
            seg0.set_qp_type(desc.qp_type as u64);
            seg0.set_rq_access_flags(desc.rq_acc_flags.bits().into());
            seg0.set_pmtu(desc.pmtu.clone() as u64);
        }

        fn write_set_network_param(dst: &mut [u8], desc: &ToCardCtrlRbDescSetNetworkParam) {
            let mut network_params = CmdQueueReqDescSetNetworkParam(dst);
            network_params.set_eth_mac_addr(u8_slice_to_u64(desc.macaddr.as_bytes()));
            network_params.set_ip_addr(u8_slice_to_u64(&desc.ipaddr.octets()));
            network_params.set_ip_gateway(u8_slice_to_u64(&desc.gateway.octets()));
            network_params.set_ip_netmask(u8_slice_to_u64(&desc.netmask.octets()));
        }

        fn write_set_raw_packet_receive_meta(
            dst: &mut [u8],
            desc: &ToCardCtrlRbDescSetRawPacketReceiveMeta,
        ) {
            let mut raw_packet_recv_meta = CmdQueueReqDescSetRawPacketReceiveMeta(dst);
            raw_packet_recv_meta.set_write_base_addr(desc.base_write_addr);
            raw_packet_recv_meta.set_write_mr_key(desc.key.get() as u64);
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
            ToCardCtrlRbDesc::SetNetworkParam(desc) => {
                write_common_header(dst, CtrlRbDescOpcode::SetNetworkParam, desc.common.op_id);
                write_set_network_param(dst, desc);
            }
            ToCardCtrlRbDesc::SetRawPacketReceiveMeta(desc) => {
                write_common_header(
                    dst,
                    CtrlRbDescOpcode::SetRawPacketReceiveMeta,
                    desc.common.op_id,
                );
                write_set_raw_packet_receive_meta(dst, desc);
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
        let mut head = CmdQueueDescCommonHead(src);

        let valid = head.get_valid();
        assert!(valid);

        let extra_segment_cnt = head.get_extra_segment_cnt();
        assert!(extra_segment_cnt == 0);

        let is_success = head.get_is_success_or_need_signal_cplt();
        let opcode = CtrlRbDescOpcode::try_from(head.get_op_code() as u8).unwrap();
        let op_id = head.get_user_data().to_le();

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
            CtrlRbDescOpcode::SetNetworkParam => {
                ToHostCtrlRbDesc::SetNetworkParam(ToHostCtrlRbDescSetNetworkParam { common })
            }
            CtrlRbDescOpcode::SetRawPacketReceiveMeta => {
                ToHostCtrlRbDesc::SetRawPacketReceiveMeta(ToHostCtrlRbDescSetRawPacketReceiveMeta {
                    common,
                })
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
                (&desc.common, ToCardWorkRbDescOpcode::Read, true, true)
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
            ToCardWorkRbDesc::ReadResp(desc) => (
                &desc.common,
                ToCardWorkRbDescOpcode::ReadResp,
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
        let mut head = SendQueueDescCommonHead(dst);
        head.set_valid(true);
        head.set_is_success_or_need_signal_cplt(false);
        head.set_is_first(is_first);
        head.set_is_last(is_last);
        head.set_op_code(opcode as u32);

        let extra_segment_cnt = self.serialized_desc_cnt() - 1;
        head.set_extra_segment_cnt(extra_segment_cnt as u32);
        head.set_total_len(common.total_len);

        // typedef struct {
        //     ReservedZero#(64)           reserved1;        // 64 bits
        //     AddrIPv4                    dqpIP;            // 32 bits
        //     RKEY                        rkey;             // 32 bits
        //     ADDR                        raddr;            // 64 bits
        //     SendQueueDescCommonHead     commonHeader;     // 64 bits
        // } SendQueueReqDescSeg0 deriving(Bits, FShow);
        // let mut seg0 = SendQueueReqDescSeg0(&mut dst[8..]);
        let dst = &mut head.0;
        let mut head = SendQueueReqDescSeg0(dst);
        head.set_raddr(common.raddr);
        head.set_rkey(common.rkey.get().into());
        head.0[20..24].copy_from_slice(&common.dqp_ip.octets());
    }

    pub(super) fn write_1(&self, dst: &mut [u8]) {
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
            ToCardWorkRbDesc::ReadResp(desc) => (
                &desc.common,
                1 + desc.sge1.is_some() as u8
                    + desc.sge2.is_some() as u8
                    + desc.sge3.is_some() as u8,
            ),
        };
        let mut desc_common = SendQueueReqDescSeg1(dst);
        desc_common.set_pmtu(common.pmtu.clone() as u64);
        desc_common.set_flags(common.flags.bits().into());
        desc_common.set_qp_type(common.qp_type as u64);
        desc_common.set_seg_cnt(sge_cnt.into());
        desc_common.set_psn(common.psn.get().into());
        let mac = &common.mac_addr;
        desc_common.0[8..14].copy_from_slice(&[mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]]);

        desc_common.set_dqpn(common.dqpn.get().into());

        if let ToCardWorkRbDesc::WriteWithImm(desc) = self {
            desc_common.set_imm(desc.imm as u64);
        } else {
            desc_common.set_imm(0);
        }
    }

    pub(super) fn write_2(&self, dst: &mut [u8]) {
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
            ToCardWorkRbDesc::ReadResp(desc) => (&desc.sge0, desc.sge1.as_ref()),
        };

        let mut frag_sge = SendQueueReqDescFragSGE(&mut dst[16..32]);
        frag_sge.set_laddr(sge0.addr);
        frag_sge.set_len(sge0.len.into());
        frag_sge.set_lkey(sge0.key.get().into());

        let mut frag_sge = SendQueueReqDescFragSGE(&mut dst[0..16]);
        if let Some(sge1) = sge1 {
            frag_sge.set_laddr(sge1.addr);
            frag_sge.set_len(sge1.len.into());
            frag_sge.set_lkey(sge1.key.get().into());
        } else {
            dst[0..16].copy_from_slice(&[0; 16]);
        }
    }

    pub(super) fn write_3(&self, dst: &mut [u8]) {
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
            ToCardWorkRbDesc::Read(_) => (None, None),
            ToCardWorkRbDesc::Write(desc) => (desc.sge2.as_ref(), desc.sge3.as_ref()),
            ToCardWorkRbDesc::WriteWithImm(desc) => (desc.sge2.as_ref(), desc.sge3.as_ref()),
            ToCardWorkRbDesc::ReadResp(desc) => (desc.sge2.as_ref(), desc.sge3.as_ref()),
        };

        let mut frag_sge = SendQueueReqDescFragSGE(&mut dst[0..16]);
        if let Some(sge3) = sge3 {
            frag_sge.set_lkey(sge3.key.get().into());
            frag_sge.set_len(sge3.len.into());
            frag_sge.set_laddr(sge3.addr);
        } else {
            frag_sge.set_lkey(0);
            frag_sge.set_len(0);
            frag_sge.set_laddr(0);
        }

        let mut frag_sge = SendQueueReqDescFragSGE(&mut dst[16..32]);
        if let Some(sge2) = sge2 {
            frag_sge.set_lkey(sge2.key.get().into());
            frag_sge.set_len(sge2.len.into());
            frag_sge.set_laddr(sge2.addr);
        } else {
            frag_sge.set_lkey(0);
            frag_sge.set_len(0);
            frag_sge.set_laddr(0);
        }
    }

    pub(super) fn serialized_desc_cnt(&self) -> usize {
        let sge_desc_cnt = match self {
            ToCardWorkRbDesc::Read(_) => 1,
            ToCardWorkRbDesc::Write(desc) => 1 + desc.sge2.is_some() as usize,
            ToCardWorkRbDesc::WriteWithImm(desc) => 1 + desc.sge2.is_some() as usize,
            ToCardWorkRbDesc::ReadResp(desc) => 1 + desc.sge2.is_some() as usize,
        };

        2 + sge_desc_cnt
    }
}

impl ToHostWorkRbDesc {
    pub(super) fn read(src: &[u8]) -> Result<ToHostWorkRbDesc, IncompleteToHostWorkRbDesc> {
        /// (addr, key, len)
        fn read_reth(src: &[u8]) -> (u64, Key, u32) {
            // typedef struct {
            //     Length                  dlen;         // 32
            //     RKEY                    rkey;         // 32
            //     ADDR                    va;           // 64
            // } MeatReportQueueDescFragRETH deriving(Bits, FShow);

            // first 12 bytes are desc type, status and bth
            let mut frag_reth = MeatReportQueueDescFragRETH(&src[12..]);
            let addr = frag_reth.get_va();
            let key = Key::new(frag_reth.get_rkey() as u32);
            let len = frag_reth.get_dlen() as u32;

            (addr, key, len)
        }

        fn read_imm(src: &[u8]) -> u32 {
            // typedef struct {
            //     IMM                             data;           // 32
            // } MeatReportQueueDescFragImmDT deriving(Bits, FShow);

            // first 28 bytes are desc type, status, bth and reth
            let mut imm = MeatReportQueueDescFragImmDT(&src[28..32]);
            // call the `to_be` to convert order
            imm.get_imm()
        }

        // (last_psn, msn, value, code)
        fn read_aeth(src: &[u8]) -> (Psn, Msn, u8, ToHostWorkRbDescAethCode) {
            // typedef struct {
            //     AethCode                code;         // 3
            //     AethValue               value;        // 5
            //     MSN                     msn;          // 24
            //     PSN                     lastRetryPSN; // 24
            // } MeatReportQueueDescFragAETH deriving(Bits, FShow);

            // first 12 bytes are desc type, status and bth
            let mut frag_aeth = MeatReportQueueDescFragAETH(&src[12..]);
            let psn = Psn::new(frag_aeth.get_psn());
            let msn = Msn::new(frag_aeth.get_msn());
            let value = frag_aeth.get_aeth_value() as u8;
            let code = ToHostWorkRbDescAethCode::try_from(frag_aeth.get_aeth_code() as u8).unwrap();

            (psn, msn, value, code)
        }

        // typedef struct {
        //     ReservedZero#(160)              reserved1;      // 160
        //     MeatReportQueueDescFragBTH      bth;            // 64
        //     RdmaReqStatus                   reqStatus;      // 8
        //     ReservedZero#(23)               reserved2;      // 23
        //     MeatReportQueueDescType         descType;       // 1
        // } MeatReportQueueDescBth deriving(Bits, FShow);
        let desc_bth = MeatReportQueueDescBth(&src[0..32]);
        let is_pkt_meta = desc_bth.get_desc_type();
        assert!(is_pkt_meta); // only support pkt meta for now

        let status = ToHostWorkRbDescStatus::try_from(desc_bth.get_req_status() as u8).unwrap();

        // typedef struct {
        //     ReservedZero#(4)                reserved1;    // 4
        //     PAD                             padCnt;       // 2
        //     Bool                            ackReq;       // 1
        //     Bool                            solicited;    // 1
        //     PSN                             psn;          // 24
        //     QPN                             dqpn;         // 24
        //     RdmaOpCode                      opcode;       // 5
        //     TransType                       trans;        // 3
        // } MeatReportQueueDescFragBTH deriving(Bits, FShow);

        let desc_frag_bth = MeatReportQueueDescFragBTH(&src[4..32]);
        let trans =
            ToHostWorkRbDescTransType::try_from(desc_frag_bth.get_trans_type() as u8).unwrap();
        let opcode = ToHostWorkRbDescOpcode::try_from(desc_frag_bth.get_opcode() as u8).unwrap();
        let dqpn = Qpn::new(desc_frag_bth.get_qpn());
        let psn = Psn::new(desc_frag_bth.get_psn());
        let pad_cnt = desc_frag_bth.get_pad_cnt() as u8;

        let common = ToHostWorkRbDescCommon {
            status,
            trans,
            dqpn,
            pad_cnt,
        };

        match opcode {
            ToHostWorkRbDescOpcode::RdmaWriteFirst => {
                let (addr, key, len) = read_reth(src);

                Ok(ToHostWorkRbDesc::Write(ToHostWorkRbDescWrite {
                    common,
                    write_type: ToHostWorkRbDescWriteType::First,
                    psn,
                    addr,
                    len,
                    key,
                }))
            }
            ToHostWorkRbDescOpcode::RdmaWriteMiddle => {
                let (addr, key, len) = read_reth(src);

                Ok(ToHostWorkRbDesc::Write(ToHostWorkRbDescWrite {
                    common,
                    write_type: ToHostWorkRbDescWriteType::Middle,
                    psn,
                    addr,
                    len,
                    key,
                }))
            }
            ToHostWorkRbDescOpcode::RdmaWriteLast => {
                let (addr, key, len) = read_reth(src);

                Ok(ToHostWorkRbDesc::Write(ToHostWorkRbDescWrite {
                    common,
                    write_type: ToHostWorkRbDescWriteType::Last,
                    psn,
                    addr,
                    len,
                    key,
                }))
            }
            ToHostWorkRbDescOpcode::RdmaWriteOnly => {
                let (addr, key, len) = read_reth(src);

                Ok(ToHostWorkRbDesc::Write(ToHostWorkRbDescWrite {
                    common,
                    write_type: ToHostWorkRbDescWriteType::Only,
                    psn,
                    addr,
                    len,
                    key,
                }))
            }
            ToHostWorkRbDescOpcode::RdmaWriteLastWithImmediate => {
                let (addr, key, len) = read_reth(src);
                let imm = read_imm(src);

                Ok(ToHostWorkRbDesc::WriteWithImm(
                    ToHostWorkRbDescWriteWithImm {
                        common,
                        write_type: ToHostWorkRbDescWriteType::Last,
                        psn,
                        imm,
                        addr,
                        len,
                        key,
                    },
                ))
            }
            ToHostWorkRbDescOpcode::RdmaWriteOnlyWithImmediate => {
                let (addr, key, len) = read_reth(src);
                let imm = read_imm(src);

                Ok(ToHostWorkRbDesc::WriteWithImm(
                    ToHostWorkRbDescWriteWithImm {
                        common,
                        write_type: ToHostWorkRbDescWriteType::Only,
                        psn,
                        imm,
                        addr,
                        len,
                        key,
                    },
                ))
            }
            ToHostWorkRbDescOpcode::RdmaReadRequest => {
                let (addr, key, len) = read_reth(src);

                Err(IncompleteToHostWorkRbDesc {
                    parsed: ToHostWorkRbDesc::Read(ToHostWorkRbDescRead {
                        common,
                        len,
                        laddr: addr,
                        lkey: key,
                        raddr: 0,
                        rkey: Key::default(),
                    }),
                    parsed_cnt: 1,
                })
            }
            ToHostWorkRbDescOpcode::Acknowledge => {
                let (last_psn, msn, value, code) = read_aeth(src);

                match code {
                    ToHostWorkRbDescAethCode::Ack => {
                        Ok(ToHostWorkRbDesc::Ack(ToHostWorkRbDescAck {
                            common,
                            msn,
                            value,
                            psn,
                        }))
                    }
                    ToHostWorkRbDescAethCode::Nak => {
                        Ok(ToHostWorkRbDesc::Nack(ToHostWorkRbDescNack {
                            common,
                            msn,
                            value,
                            lost_psn: psn..last_psn,
                        }))
                    }
                    ToHostWorkRbDescAethCode::Rnr => unimplemented!(),
                    ToHostWorkRbDescAethCode::Rsvd => unimplemented!(),
                }
            }
            _ => unimplemented!(),
        }
    }

    pub(super) fn serialized_desc_cnt(&self) -> usize {
        match self {
            ToHostWorkRbDesc::Read(_) => 2,
            ToHostWorkRbDesc::Write(_) => 1,
            ToHostWorkRbDesc::WriteWithImm(_) => 1,
            ToHostWorkRbDesc::Ack(_) => 1,
            ToHostWorkRbDesc::Nack(_) => 1,
        }
    }
}

impl IncompleteToHostWorkRbDesc {
    #[allow(unreachable_code)]
    pub(super) fn read(self, src: &[u8]) -> Result<ToHostWorkRbDesc, IncompleteToHostWorkRbDesc> {
        fn read_second_reth(src: &[u8]) -> (u64, Key) {
            // typedef struct {
            //     RKEY                            secondaryRkey;   // 32
            //     ADDR                            secondaryVa;     // 64
            // } MeatReportQueueDescFragSecondaryRETH deriving(Bits, FShow);
            let secondary_reth = MeatReportQueueDescFragSecondaryRETH(&src);
            let addr = secondary_reth.get_secondary_va();
            let key = Key::new(secondary_reth.get_secondary_rkey() as u32);

            (addr, key)
        }

        match self.parsed {
            ToHostWorkRbDesc::Read(mut desc) => match self.parsed_cnt {
                1 => {
                    let (raddr, rkey) = read_second_reth(src);
                    desc.raddr = raddr;
                    desc.rkey = rkey;
                    return Ok(ToHostWorkRbDesc::Read(desc));
                }
                _ => unreachable!(),
            },
            ToHostWorkRbDesc::Write(_) => unreachable!(),
            ToHostWorkRbDesc::WriteWithImm(_) => unreachable!(),
            ToHostWorkRbDesc::Ack(_) => unreachable!(),
            ToHostWorkRbDesc::Nack(_) => unreachable!(),
        }

        self.parsed_cnt += 1;
        Err(self)
    }
}

bitfield! {
    struct CmdQueueDescCommonHead([u8]);
    u32;
    get_valid , set_valid: 0;
    get_is_success_or_need_signal_cplt, set_is_success_or_need_signal_cplt: 1;
    get_op_code, set_op_code: 7, 2;
    get_extra_segment_cnt, set_extra_segment_cnt: 11, 8;
    _reserverd, _: 31, 12;
    get_user_data, set_user_data: 63, 32;
}

bitfield! {
    struct CmdQueueReqDescUpdateMrTable([u8]);
    u64;
    _cmd_queue_desc_common_head,_: 63, 0;      // 64bits
    get_mr_base_va, set_mr_base_va: 127, 64;   // 64bits
    get_mr_length, set_mr_length: 159, 128;    // 32bits
    get_mr_key, set_mr_key: 191, 160;          // 32bits
    get_pd_handler, set_pd_handler: 223, 192;  // 32bits
    get_acc_flags, set_acc_flags: 231, 224;    // 8bits
    get_pgt_offset, set_pgt_offset: 248, 232;  // 17bits
    _reserved0, _: 255, 249;                   // 7bits
}

bitfield! {
    struct CmdQueueReqDescUpdatePGT([u8]);
    u64;
    __cmd_queue_desc_common_head,_ : 63, 0;             // 64bits
    get_dma_addr, set_dma_addr: 127, 64;                // 64bits
    get_start_index, set_start_index: 159, 128;         // 32bits
    get_dma_read_length, set_dma_read_length: 191, 160; // 32bits
    _reserved0, _: 255, 192;                            // 64bits
}

bitfield! {
    struct CmdQueueReqDescQpManagementSeg0([u8]);
    u64;
    _cmd_queue_desc_common_head,_: 63, 0;                                       // 64bits
    get_is_valid, set_is_valid: 64;                                             // 1bit
    get_is_error, set_is_error: 65;                                             // 1bit
    _reserverd4, _: 71, 66;                                                     // 6bits
    get_qpn, set_qpn: 96, 72;                                                   // 24bits
    get_pd_handler, set_pd_handler: 128, 97;                                    // 32bits
    get_qp_type, set_qp_type: 132, 129;                                         // 4bits
    _reserverd3, _: 136, 133;                                                   // 4bits
    get_rq_access_flags, set_rq_access_flags: 144, 137;                         // 8bits
    get_pmtu, set_pmtu: 147, 145;                                               // 3bits
    _reserverd2, _: 151, 148;                                                   // 5bits
    _reserverd1, _: 255, 152;                                                   // 104bits
}

bitfield! {
    struct CmdQueueReqDescSetNetworkParam([u8]);
    u64;
    _cmd_queue_desc_common_head,_:          63 ,   0;                                       // 64bits
    get_ip_gateway, set_ip_gateway:         95 ,  64;                                       // 32bits
    get_ip_netmask, set_ip_netmask:         127,  96;                                       // 32bit
    get_ip_addr, set_ip_addr:               159, 128;                                       // 32bit
    _reserverd1, _:                         191, 160;                                       // 32bit
    get_eth_mac_addr, set_eth_mac_addr:     239, 192;                                       // 48bit
    _reserverd2, _:                         255, 240;                                       // 16bit
}

bitfield! {
    struct CmdQueueReqDescSetRawPacketReceiveMeta([u8]);
    u64;
    _cmd_queue_desc_common_head,_:              63 ,   0;                                   // 64bits
    get_write_base_addr, set_write_base_addr:   127,  64;                                   // 64bits
    get_write_mr_key, set_write_mr_key:         159, 128;                                   // 32bits
    _reserverd1, _:                             191, 160;                                   // 32bits
    _reserverd2, _:                             255, 240;                                   // 64bits
}

bitfield! {
    struct SendQueueDescCommonHead([u8]);
    u32;
    get_valid , set_valid: 0;                                                  // 1bit
    get_is_success_or_need_signal_cplt, set_is_success_or_need_signal_cplt: 1; // 1bit
    get_is_first, set_is_first: 2;                                             // 1bit
    get_is_last, set_is_last: 3;                                               // 1bit
    get_op_code, set_op_code: 7, 4;                                            // 4bits
    get_extra_segment_cnt, set_extra_segment_cnt: 11, 8;                       // 4bits
    _reserverd, _: 31, 12;                                                     // 20bits
    get_total_len, set_total_len: 63, 32;                                      // 32bits
}

bitfield! {
    struct SendQueueReqDescSeg0([u8]);
    u64;
    _common_header, _: 63, 0;         // 64bits
    get_raddr, set_raddr: 127, 64;    // 64bits
    get_rkey, set_rkey: 159, 128;     // 32bits
    get_dqp_ip, set_dqp_ip: 191, 160; // 32bits
    _reserverd, _: 255, 192;          // 64bits
}

bitfield! {
    struct SendQueueReqDescSeg1([u8]);
    u64;
    get_pmtu, set_pmtu: 2, 0;             // 3bits
    _reserved8 , _: 7, 3;                 // 5bits
    get_flags, set_flags: 12, 8;          // 5bits
    _reserved7 , _: 15, 13;               // 3bits
    get_qp_type, set_qp_type: 19, 16;     // 4bits
    _reserved6 , _: 23, 20;               // 4bits
    get_seg_cnt, set_seg_cnt: 26, 24;     // 3bits
    _reserved5 , _: 31, 27;               // 5bits
    get_psn, set_psn: 55, 32;             // 24bits
    _reserved4 , _: 63, 56;               // 8bits
    get_mac_addr, set_mac_addr: 111, 64;  // 48bits
    _reserved3 , _: 127, 112;             // 16bits
    get_dqpn, set_dqpn: 151, 128;         // 24bits
    _reserved2 , _: 159, 152;             // 8bits
    get_imm, set_imm: 191, 160;           // 32bits
    _reserved1 , _: 255, 192;             // 64bits
}

bitfield! {
    struct SendQueueReqDescFragSGE([u8]);
    u64;
    get_lkey, set_lkey: 31, 0;     // 32bits
    get_len, set_len: 63, 32;      // 32bits
    get_laddr, set_laddr: 127, 64; // 64bits
}

bitfield! {
    struct MeatReportQueueDescFragRETH([u8]);
    u64;
    get_va, set_va: 63, 0;          // 64bits
    get_rkey, set_rkey: 95, 64;     // 32bits
    get_dlen, set_dlen: 127, 96;    // 32bits
}

bitfield! {
    struct MeatReportQueueDescFragImmDT([u8]);
    u32;
    get_imm, set_imm: 32, 0;          // 32bits
}

bitfield! {
    struct MeatReportQueueDescFragAETH([u8]);
    u32;
    get_psn, set_psn: 23, 0;          // 24bits
    get_msn, set_msn: 47, 24;         // 24bits
    get_aeth_value, set_aeth_value: 52, 48; // 5bits
    get_aeth_code, set_aeth_code: 55, 53;   // 3bits
}
bitfield! {
    struct MeatReportQueueDescBth([u8]);
    u64;
    get_desc_type, set_desc_type: 0; // 1bit
    reserved2,_ : 23, 1;              // 23bits
    get_req_status, set_req_status: 31,24; // 8bit
    get_bth, set_bth: 95, 32;         // 64bits
    reserved1,_ : 255, 96;            // 160bits
}

bitfield! {
    struct MeatReportQueueDescFragBTH([u8]);
    u32;
    get_trans_type,set_trans_type: 2, 0; // 3bits
    get_opcode,set_opcode: 7, 3;         // 5bits
    get_qpn,set_qpn: 31, 8;              // 24bits
    get_psn,set_psn: 55, 32;             // 24bits
    get_solicited,set_solicited: 56;     // 1bit
    get_ack_req,set_ack_req: 57;         // 1bit
    get_pad_cnt,set_pad_cnt: 63, 58;     // 4bits
}

bitfield! {
    struct MeatReportQueueDescFragSecondaryRETH([u8]);
    u64;
    get_secondary_va,set_secondary_va: 63, 0; // 64bits
    get_secondary_rkey,set_secondary_rkey: 95, 64; // 32bits
}

pub(crate) struct ToCardWorkRbDescBuilder {
    type_: ToCardWorkRbDescOpcode,
    common: Option<ToCardWorkRbDescCommon>,
    seg_list: Vec<Sge>,
    is_first: Option<bool>,
    is_last: Option<bool>,
    imm: Option<u32>,
}

impl ToCardWorkRbDescBuilder {
    pub fn new_write() -> Self {
        Self {
            type_: ToCardWorkRbDescOpcode::Write,
            common: None,
            seg_list: Vec::new(),
            is_first: None,
            is_last: None,
            imm: None,
        }
    }

    pub fn new_write_imm() -> Self {
        Self {
            type_: ToCardWorkRbDescOpcode::WriteWithImm,
            common: None,
            seg_list: Vec::new(),
            is_first: None,
            is_last: None,
            imm: None,
        }
    }

    pub fn new_read_resp() -> Self {
        Self {
            type_: ToCardWorkRbDescOpcode::ReadResp,
            common: None,
            seg_list: Vec::new(),
            is_first: None,
            is_last: None,
            imm: None,
        }
    }

    pub fn new_read() -> Self {
        Self {
            type_: ToCardWorkRbDescOpcode::Read,
            common: None,
            seg_list: Vec::new(),
            is_first: None,
            is_last: None,
            imm: None,
        }
    }

    pub fn with_common(mut self, common: ToCardWorkRbDescCommon) -> Self {
        self.common = Some(common);
        self
    }

    pub fn with_option_sge(mut self, seg: Option<Sge>) -> Self {
        if let Some(seg) = seg {
            self.seg_list.push(seg);
        }
        self
    }

    pub fn with_sge(mut self, seg: Sge) -> Self {
        self.seg_list.push(seg);
        self
    }

    pub fn with_is_first(mut self, is_first: bool) -> Self {
        self.is_first = Some(is_first);
        self
    }

    pub fn with_is_last(mut self, is_last: bool) -> Self {
        self.is_last = Some(is_last);
        self
    }

    pub fn with_imm(mut self, imm: u32) -> Self {
        self.imm = Some(imm);
        self
    }

    pub fn build(mut self) -> Result<ToCardWorkRbDesc, Error> {
        let common = self
            .common
            .ok_or_else(|| Error::BuildDescFailed("common"))?;
        match self.type_ {
            ToCardWorkRbDescOpcode::Write => {
                let sge0 = self
                    .seg_list
                    .pop()
                    .ok_or_else(|| Error::BuildDescFailed("sge"))?;
                let sge1 = self.seg_list.pop();
                let sge2 = self.seg_list.pop();
                let sge3 = self.seg_list.pop();
                let total_len = sge0.len
                    + sge1.as_ref().map_or(0, |sge| sge.len)
                    + sge2.as_ref().map_or(0, |sge| sge.len)
                    + sge3.as_ref().map_or(0, |sge| sge.len);
                Ok(ToCardWorkRbDesc::Write(ToCardWorkRbDescWrite {
                    common,
                    is_last: true,
                    is_first: true,
                    sge0: sge0.into(),
                    sge1: sge1.map(|sge| sge.into()),
                    sge2: sge2.map(|sge| sge.into()),
                    sge3: sge3.map(|sge| sge.into()),
                }))
            }
            ToCardWorkRbDescOpcode::WriteWithImm => {
                let sge0 = self
                    .seg_list
                    .pop()
                    .ok_or_else(|| Error::BuildDescFailed("sge"))?;
                let sge1 = self.seg_list.pop();
                let sge2 = self.seg_list.pop();
                let sge3 = self.seg_list.pop();
                let total_len = sge0.len
                    + sge1.as_ref().map_or(0, |sge| sge.len)
                    + sge2.as_ref().map_or(0, |sge| sge.len)
                    + sge3.as_ref().map_or(0, |sge| sge.len);
                let imm = self.imm.ok_or_else(|| Error::BuildDescFailed("imm"))?;
                Ok(ToCardWorkRbDesc::WriteWithImm(
                    ToCardWorkRbDescWriteWithImm {
                        common,
                        is_last: true,
                        is_first: true,
                        imm,
                        sge0: sge0.into(),
                        sge1: sge1.map(|sge| sge.into()),
                        sge2: sge2.map(|sge| sge.into()),
                        sge3: sge3.map(|sge| sge.into()),
                    },
                ))
            }
            ToCardWorkRbDescOpcode::Read => {
                let sge0 = self
                    .seg_list
                    .pop()
                    .ok_or_else(|| Error::BuildDescFailed("sge"))?;
                let total_len = sge0.len;
                Ok(ToCardWorkRbDesc::Read(ToCardWorkRbDescRead {
                    common,
                    sge: sge0.into(),
                }))
            }
            ToCardWorkRbDescOpcode::ReadResp => {
                let sge0 = self
                    .seg_list
                    .pop()
                    .ok_or_else(|| Error::BuildDescFailed("sge"))?;
                let sge1 = self.seg_list.pop();
                let sge2 = self.seg_list.pop();
                let sge3 = self.seg_list.pop();
                let total_len = sge0.len
                    + sge1.as_ref().map_or(0, |sge| sge.len)
                    + sge2.as_ref().map_or(0, |sge| sge.len)
                    + sge3.as_ref().map_or(0, |sge| sge.len);
                Ok(ToCardWorkRbDesc::ReadResp(ToCardWorkRbDescWrite {
                    common,
                    is_last: true,
                    is_first: true,
                    sge0: sge0.into(),
                    sge1: sge1.map(|sge| sge.into()),
                    sge2: sge2.map(|sge| sge.into()),
                    sge3: sge3.map(|sge| sge.into()),
                }))
            }
        }
    }
}
