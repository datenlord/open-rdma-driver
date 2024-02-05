#![allow(unused)]

use std::net::Ipv4Addr;

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
pub(crate) enum ToCardWorkRbDesc {
    Request(ToCardWorkRbDescRequest),
}

/// A descriptor for the to-host work ring buffer.
pub(crate) enum ToHostWorkRbDesc {
    SendQueueReport(ToHostWorkRbDescSendQueueReport),
    Bth(ToHostWorkRbDescBth),
    BthRethImmDt(ToHostWorkRbDescBthRethImmDt),
    BthAeth(ToHostWorkRbDescBthAeth),
    SecondaryReth(ToHostWorkRbDescSecondaryReth),
}

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
pub(crate) struct ToCardCtrlRbDescUpdateMrTable {
    common_header: CtrlRbDescCommonHeader,
    base_va: u64,
    mr_length: u32,
    mr_key: u32,
    pd_handler: u32,
    acc_flags: u8,
    pgt_offset: u32,
}

// typedef struct {
//     ReservedZero#(64)               reserved1;
//     Bit#(32)                        dmaReadLength;
//     Bit#(32)                        startIndex;
//     Bit#(64)                        dmaAddr;
//     CmdQueueDescCommonHead          commonHeader;
// } CmdQueueReqDescUpdatePGT deriving(Bits, FShow);
pub(crate) struct ToCardCtrlRbDescUpdatePageTable {
    common_header: CtrlRbDescCommonHeader,
    dma_addr: u64,
    start_index: u32,
    dma_read_length: u32,
}

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
pub(crate) struct ToCardCtrlRbDescQpManagement {
    common_header: CtrlRbDescCommonHeader,
    is_valid: bool,
    is_error: bool,
    qpn: u32,
    pd_handler: u32,
    qp_type: QpType,
    rq_access_flags: u8,
    pmtu: Pmtu,
}

// TODO: no corresponding struct
pub(crate) struct ToHostCtrlRbDescUpdateMrTable {
    common_header: CtrlRbDescCommonHeader,
}

// typedef struct {
//     ReservedZero#(64)               reserved1;
//     ReservedZero#(64)               reserved2;
//     ReservedZero#(64)               reserved3;
//     CmdQueueDescCommonHead          commonHeader;
// } CmdQueueRespDescUpdatePGT deriving(Bits, FShow);
pub(crate) struct ToHostCtrlRbDescUpdatePageTable {
    common_header: CtrlRbDescCommonHeader,
}

// typedef CmdQueueReqDescQpManagementSeg0 CmdQueueRespDescQpManagementSeg0;
pub(crate) struct ToHostCtrlRbDescQpManagement {
    common_header: CtrlRbDescCommonHeader,
    is_valid: bool,
    is_error: bool,
    qpn: u32,
    pd_handler: u32,
    qp_type: QpType,
    rq_access_flags: u8,
    pmtu: Pmtu,
}

// typedef struct {
//     ReservedZero#(64)           reserved1;        // 64 bits
//     AddrIPv4                    dqpIP;            // 32 bits
//     RKEY                        rkey;             // 32 bits
//     ADDR                        raddr;            // 64 bits
//     SendQueueDescCommonHead     commonHeader;     // 64 bits
// } SendQueueReqDescSeg0 deriving(Bits, FShow);
// typedef struct {
//     ReservedZero#(64)       reserved1;          // 64 bits
//     IMM                     imm;                // 32 bits
//     ReservedZero#(8)        reserved2;          // 8  bits
//     QPN                     dqpn;               // 24 bits
//     MAC                     macAddr;            // 48 bits
//     ReservedZero#(16)       reserved3;          // 16 bits
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
pub(crate) struct ToCardWorkRbDescRequest {
    common_header: ToCardWorkRbDescCommonHeader,
    raddr: u64,
    rkey: [u8; 4],
    dqp_ip: Ipv4Addr, // using Ipv4Addr temporarily for convenience
    pmtu: Pmtu,
    flags: u8,
    qp_type: QpType,
    sge_cnt: u8,
    psn: u32,
    mac_addr: [u8; 6],
    dqpn: u32,
    imm: [u8; 4],
    sgl: ScatterGatherList,
}

// typedef struct {
//     ReservedZero#(231)              reserved1;      // 231
//     Bool                            hasDmaRespErr;  // 1
//     ReservedZero#(23)               reserved2;      // 23
//     MeatReportQueueDescType         descType;       // 1
// } MeatReportQueueDescSendQueueReport deriving(Bits, FShow);
pub(crate) struct ToHostWorkRbDescSendQueueReport {
    desc_type: ToHostWorkRbDescType,
    has_dma_resp_err: bool,
}

// typedef struct {
//     ReservedZero#(160)              reserved1;      // 160
//     MeatReportQueueDescFragBTH      bth;            // 64
//     RdmaReqStatus                   reqStatus;      // 8
//     ReservedZero#(23)               reserved2;      // 23
//     MeatReportQueueDescType         descType;       // 1
// } MeatReportQueueDescBth deriving(Bits, FShow);
pub(crate) struct ToHostWorkRbDescBth {
    desc_type: ToHostWorkRbDescType,
    bth: ToHostWorkRbDescFragBth,
    req_status: RdmaReqStatus,
}

// typedef struct {
//     MeatReportQueueDescFragImmDT    immDt;          // 32
//     MeatReportQueueDescFragRETH     reth;           // 128
//     MeatReportQueueDescFragBTH      bth;            // 64
//     RdmaReqStatus                   reqStatus;      // 8
//     ReservedZero#(23)               reserved1;      // 23
//     MeatReportQueueDescType         descType;       // 1
// } MeatReportQueueDescBthRethImmDT deriving(Bits, FShow);
pub(crate) struct ToHostWorkRbDescBthRethImmDt {
    desc_type: ToHostWorkRbDescType,
    req_status: RdmaReqStatus,
    bth: ToHostWorkRbDescFragBth,
    reth: ToHostWorkRbDescFragReth,
    imm_dt: ToHostWorkRbDescFragImmDt,
}

// typedef struct {
//     ReservedZero#(105)              reserved1;      // 105
//     MeatReportQueueDescFragAETH     aeth;           // 55
//     MeatReportQueueDescFragBTH      bth;            // 64
//     RdmaReqStatus                   reqStatus;      // 8
//     ReservedZero#(23)               reserved2;      // 23
//     MeatReportQueueDescType         descType;       // 1
// } MeatReportQueueDescBthAeth deriving(Bits, FShow);
pub(crate) struct ToHostWorkRbDescBthAeth {
    desc_type: ToHostWorkRbDescType,
    req_status: RdmaReqStatus,
    bth: ToHostWorkRbDescFragBth,
    aeth: ToHostWorkRbDescFragAeth,
}

// typedef struct {
//     ReservedZero#(160)                          reserved1;       // 160
//     MeatReportQueueDescFragSecondaryRETH        secReth;         // 96
// } MeatReportQueueDescSecondaryReth deriving(Bits, FShow);
pub(crate) struct ToHostWorkRbDescSecondaryReth {
    sec_reth: ToHostWorkRbDescFragSecondaryReth,
}

// typedef struct {
//     Bit#(32)                userData;
//     ReservedZero#(20)       reserved1;
//     Bool                    isSuccessOrNeedSignalCplt;
//     Bit#(4)                 extraSegmentCnt;
//     Bit#(6)                 opCode;
//     Bool                    valid;
// } CmdQueueDescCommonHead deriving(Bits, FShow);
pub(crate) struct CtrlRbDescCommonHeader {
    valid: bool,
    opcode: CtrlRbDescOpcode,
    extra_segment_cnt: u8,
    is_success_or_need_signal_cplt: bool,
    user_data: [u8; 4],
}

// typedef enum {
//     CmdQueueOpcodeUpdateMrTable = 'h0,
//     CmdQueueOpcodeUpdatePGT = 'h1,
//     CmdQueueOpcodeQpManagement = 'h2
// } CommandQueueOpcode deriving(Bits, Eq);
pub(crate) enum CtrlRbDescOpcode {
    UpdateMrTable = 0x00,
    UpdatePageTable = 0x01,
    QpManagement = 0x02,
}

// typedef struct {
//     Length                  totalLen;
//     ReservedZero#(20)       reserved1;
//     Bool                    isSuccessOrNeedSignalCplt;
//     Bit#(4)                 extraSegmentCnt;
//     Bool                    isFirst;
//     Bool                    isLast;
//     WorkReqOpCode           opCode;
//     Bool                    valid;
// } SendQueueDescCommonHead deriving(Bits, FShow);
pub(crate) struct ToCardWorkRbDescCommonHeader {
    valid: bool,
    opcode: ToCardWorkRbDescOpcode,
    is_last: bool,
    is_first: bool,
    extra_segment_cnt: u8,
    is_success_or_need_signal_cplt: bool,
    total_len: u32,
}

// typedef enum {
//     IBV_WR_RDMA_WRITE           =  0,
//     IBV_WR_RDMA_WRITE_WITH_IMM  =  1,
//     IBV_WR_SEND                 =  2,
//     IBV_WR_SEND_WITH_IMM        =  3,
//     IBV_WR_RDMA_READ            =  4,
//     IBV_WR_ATOMIC_CMP_AND_SWP   =  5,
//     IBV_WR_ATOMIC_FETCH_AND_ADD =  6,
//     IBV_WR_LOCAL_INV            =  7,
//     IBV_WR_BIND_MW              =  8,
//     IBV_WR_SEND_WITH_INV        =  9,
//     IBV_WR_TSO                  = 10,
//     IBV_WR_DRIVER1              = 11
// } WorkReqOpCode deriving(Bits, Eq, FShow);
pub(crate) enum ToCardWorkRbDescOpcode {
    RdmaWrite = 0,
    RdmaWriteWithImm = 1,
    Send = 2,
    SendWithImm = 3,
    RdmaRead = 4,
    AtomicCmpAndSwp = 5,
    AtomicFetchAndAdd = 6,
    LocalInv = 7,
    BindMw = 8,
    SendWithInv = 9,
    Tso = 10,
    Driver1 = 11,
}

// typedef struct {
//     ReservedZero#(6)                reserved1;    // 6
//     Bool                            ackReq;       // 1
//     Bool                            solicited;    // 1
//     PSN                             psn;          // 24
//     QPN                             dqpn;         // 24
//     RdmaOpCode                      opcode;       // 5
//     TransType                       trans;        // 3
// } MeatReportQueueDescFragBTH deriving(Bits, FShow);
pub(crate) struct ToHostWorkRbDescFragBth {
    trans: TransType,
    opcode: RdmaOpcode,
    dqpn: u32,
    psn: u32,
    solicited: bool,
    ack_req: bool,
}

// typedef struct {
//     Length                  dlen;         // 32
//     RKEY                    rkey;         // 32
//     ADDR                    va;           // 64
// } MeatReportQueueDescFragRETH deriving(Bits, FShow);
pub(crate) struct ToHostWorkRbDescFragReth {
    va: u64,
    rkey: [u8; 4],
    dlen: u32,
}

// typedef struct {
//     AethCode                code;         // 2
//     AethValue               value;        // 5
//     MSN                     msn;          // 24
//     PSN                     lastRetryPSN; // 24
// } MeatReportQueueDescFragAETH deriving(Bits, FShow);
pub(crate) struct ToHostWorkRbDescFragAeth {
    last_retry_psn: u32,
    msn: u32,
    value: u8,
    code: AethCode,
}

// typedef struct {
//     RKEY                            secondaryRkey;   // 32
//     ADDR                            secondaryVa;     // 64
// } MeatReportQueueDescFragSecondaryRETH deriving(Bits, FShow);
pub(crate) struct ToHostWorkRbDescFragSecondaryReth {
    secondary_va: u64,
    secondary_rkey: [u8; 4],
}

// typedef struct {
//     IMM                             data;           // 32
// } MeatReportQueueDescFragImmDT deriving(Bits, FShow);
pub(crate) struct ToHostWorkRbDescFragImmDt {
    data: [u8; 4],
}

// typedef enum {
//     MeatReportQueueDescTypeRecvPacketMeta = 0,
//     MeatReportQueueDescTypeSendFinished   = 1
// } MeatReportQueueDescType deriving(Bits, FShow);
pub(crate) enum ToHostWorkRbDescType {
    RecvPacketMeta = 0,
    SendFinished = 1,
}

// typedef enum {
//     IBV_QPT_RC = 2,
//     IBV_QPT_UC = 3,
//     IBV_QPT_UD = 4,
//     // IBV_QPT_RAW_PACKET = 8,
//     IBV_QPT_XRC_SEND = 9,
//     IBV_QPT_XRC_RECV = 10
//     // IBV_QPT_DRIVER = 0xff
// } TypeQP deriving(Bits, Eq, FShow);
pub(crate) enum QpType {
    Rc = 2,
    Uc = 3,
    Ud = 4,
    RawPacket = 8,
    XrcSend = 9,
    XrcRecv = 10,
}

// typedef enum {
//     IBV_MTU_256  = 1,
//     IBV_MTU_512  = 2,
//     IBV_MTU_1024 = 3,
//     IBV_MTU_2048 = 4,
//     IBV_MTU_4096 = 5
// } PMTU deriving(Bits, Eq, FShow);
pub(crate) enum Pmtu {
    Mtu256 = 1,
    Mtu512 = 2,
    Mtu1024 = 3,
    Mtu2048 = 4,
    Mtu4096 = 5,
}

// typedef enum {
//     TRANS_TYPE_RC  = 3'h0, // 3'b000
//     TRANS_TYPE_UC  = 3'h1, // 3'b001
//     TRANS_TYPE_RD  = 3'h2, // 3'b010
//     TRANS_TYPE_UD  = 3'h3, // 3'b011
//     TRANS_TYPE_CNP = 3'h4, // 3'b100
//     TRANS_TYPE_XRC = 3'h5  // 3'b101
// } TransType deriving(Bits, Bounded, Eq, FShow);
pub(crate) enum TransType {
    Rc = 0x00,
    Uc = 0x01,
    Rd = 0x02,
    Ud = 0x03,
    Cnp = 0x04,
    Xrc = 0x05,
}

// typedef enum {
//     SEND_FIRST                     = 5'h00,
//     SEND_MIDDLE                    = 5'h01,
//     SEND_LAST                      = 5'h02,
//     SEND_LAST_WITH_IMMEDIATE       = 5'h03,
//     SEND_ONLY                      = 5'h04,
//     SEND_ONLY_WITH_IMMEDIATE       = 5'h05,
//     RDMA_WRITE_FIRST               = 5'h06,
//     RDMA_WRITE_MIDDLE              = 5'h07,
//     RDMA_WRITE_LAST                = 5'h08,
//     RDMA_WRITE_LAST_WITH_IMMEDIATE = 5'h09,
//     RDMA_WRITE_ONLY                = 5'h0a,
//     RDMA_WRITE_ONLY_WITH_IMMEDIATE = 5'h0b,
//     RDMA_READ_REQUEST              = 5'h0c,
//     RDMA_READ_RESPONSE_FIRST       = 5'h0d,
//     RDMA_READ_RESPONSE_MIDDLE      = 5'h0e,
//     RDMA_READ_RESPONSE_LAST        = 5'h0f,
//     RDMA_READ_RESPONSE_ONLY        = 5'h10,
//     ACKNOWLEDGE                    = 5'h11,
//     ATOMIC_ACKNOWLEDGE             = 5'h12,
//     COMPARE_SWAP                   = 5'h13,
//     FETCH_ADD                      = 5'h14,
//     RESYNC                         = 5'h15,
//     SEND_LAST_WITH_INVALIDATE      = 5'h16,
//     SEND_ONLY_WITH_INVALIDATE      = 5'h17
// } RdmaOpCode deriving(Bits, Bounded, Eq, FShow);
pub(crate) enum RdmaOpcode {
    SendFirst = 0x00,
    SendMiddle = 0x01,
    SendLast = 0x02,
    SendLastWithImmediate = 0x03,
    SendOnly = 0x04,
    SendOnlyWithImmediate = 0x05,
    RdmaWriteFirst = 0x06,
    RdmaWriteMiddle = 0x07,
    RdmaWriteLast = 0x08,
    RdmaWriteLastWithImmediate = 0x09,
    RdmaWriteOnly = 0x0a,
    RdmaWriteOnlyWithImmediate = 0x0b,
    RdmaReadRequest = 0x0c,
    RdmaReadResponseFirst = 0x0d,
    RdmaReadResponseMiddle = 0x0e,
    RdmaReadResponseLast = 0x0f,
    RdmaReadResponseOnly = 0x10,
    Acknowledge = 0x11,
    AtomicAcknowledge = 0x12,
    CompareSwap = 0x13,
    FetchAdd = 0x14,
    Resync = 0x15,
    SendLastWithInvalidate = 0x16,
    SendOnlyWithInvalidate = 0x17,
}

// TODO: temporary struct
pub(crate) struct ScatterGatherList {
    data: [ScatterGatherElement; 1],
    len: u32,
}

// typedef struct {
//     ADDR   laddr;         // 64 bits
//     Length len;           // 32 bits
//     LKEY   lkey;          // 32 bits
// } SendQueueReqDescFragSGE deriving(Bits, FShow);
pub(crate) struct ScatterGatherElement {
    laddr: u64,
    lkey: [u8; 4],
    len: u32,
}

// typedef enum {
//     RDMA_REQ_ST_NORMAL,
//     RDMA_REQ_ST_SEQ_ERR,
//     RDMA_REQ_ST_RNR,
//     RDMA_REQ_ST_INV_REQ,
//     RDMA_REQ_ST_INV_RD,
//     RDMA_REQ_ST_RMT_ACC,
//     RDMA_REQ_ST_RMT_OP,
//     RDMA_REQ_ST_DUP,
//     RDMA_REQ_ST_ERR_FLUSH_RR,
//     RDMA_REQ_ST_DISCARD,
//     RDMA_REQ_ST_UNKNOWN
// } RdmaReqStatus deriving(Bits, Eq, FShow);
pub(crate) enum RdmaReqStatus {
    Normal,
    SeqErr,
    Rnr,
    InvReq,
    InvRd,
    RmtAcc,
    RmtOp,
    Dup,
    ErrFlushRr,
    Discard,
    Unknown,
}

// typedef enum {
//     AETH_CODE_ACK  = 2'b00,
//     AETH_CODE_RNR  = 2'b01,
//     AETH_CODE_RSVD = 2'b10,
//     AETH_CODE_NAK  = 2'b11
// } AethCode deriving(Bits, Bounded, Eq, FShow);
pub(crate) enum AethCode {
    Ack = 0b00,
    Rnr = 0b01,
    Rsvd = 0b10,
    Nak = 0b11,
}
