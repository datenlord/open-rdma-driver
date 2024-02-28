use crate::{
    device::{
        DeviceAdaptor, EmulatedDevice, HardwareDevice, QpType as DeviceQpType,
        ScatterGatherElement as DeviceScatterGatherElement,
        ScatterGatherList as DeviceScatterGatherList, SoftwareDevice, ToCardCtrlRbDesc,
        ToCardWorkRbDesc, ToCardWorkRbDescCommonHeader, ToCardWorkRbDescOpcode,
        ToCardWorkRbDescRequest,
    },
    mr::{MrCtx, MrPgt},
    pd::PdCtx,
    qp::QpCtx,
};
use std::{
    array,
    collections::{hash_map::Entry, HashMap},
    error::Error as StdError,
    mem,
    net::Ipv4Addr,
    ops::Range,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc, Mutex, OnceLock,
    },
    thread::{self, Thread},
    time::Duration,
    vec,
};
use thiserror::Error;

mod device;
mod poll;

pub mod mr;
pub mod pd;
pub mod qp;

pub use crate::{mr::Mr, pd::Pd, qp::Qp};

const MR_KEY_IDX_BIT_CNT: usize = 10;
const MR_TABLE_SIZE: usize = 64;
const MR_PGT_SIZE: usize = 1024;

#[derive(Clone)]
pub struct Device(Arc<DeviceInner<dyn DeviceAdaptor>>);

struct DeviceInner<D: ?Sized> {
    #[allow(unused)]
    is_hardware: bool,
    pd: Mutex<HashMap<Pd, PdCtx>>,
    mr_table: Mutex<[Option<MrCtx>; MR_TABLE_SIZE]>,
    qp: Mutex<HashMap<Qp, QpCtx>>,
    mr_pgt: Mutex<MrPgt>,
    ctrl_op_ctx: Mutex<HashMap<[u8; 4], CtrlOpCtx>>,
    send_op_ctx: Mutex<HashMap<Qp, SendOpCtx>>,
    recv_op_ctx: Mutex<HashMap<Qp, RecvOpCtx>>,
    revc_pkt_map: RecvPktMap, // TODO: extend to support multiple QPs
    check_recv_pkt_comp_thread: OnceLock<Thread>,
    adaptor: D,
}

pub struct ScatterGatherElement {
    laddr: u64,
    lkey: [u8; 4],
    len: u32,
}

struct CtrlOpCtx {
    thread: Thread,
    result: Option<bool>,
}

struct SendOpCtx {
    thread: Thread,
    result: Option<bool>,
}

struct RecvOpCtx {
    thread: Thread,
    result: Option<bool>,
}

struct RecvPktMap {
    start_psn: u32,
    stage_0: Box<[u64]>,
    stage_0_last_chunk: u64,
    stage_1: Box<[u64]>,
    stage_1_last_chunk: u64,
    stage_2: Box<[u64]>,
    stage_2_last_chunk: u64,
}

/// Yields PSN ranges of missing packets
struct MissingPkt<'a> {
    #[allow(unused)]
    map: &'a RecvPktMap,
}

static NEXT_CTRL_OP_ID: AtomicU32 = AtomicU32::new(0);

impl Device {
    const MR_TABLE_EMPTY_ELEM: Option<MrCtx> = None;

    pub fn new_hardware() -> Result<Self, Error> {
        let inner = Arc::new(DeviceInner {
            is_hardware: true,
            pd: Mutex::new(HashMap::new()),
            mr_table: Mutex::new([Self::MR_TABLE_EMPTY_ELEM; MR_TABLE_SIZE]),
            qp: Mutex::new(HashMap::new()),
            mr_pgt: Mutex::new(MrPgt::new()),
            send_op_ctx: Mutex::new(HashMap::new()),
            recv_op_ctx: Mutex::new(HashMap::new()),
            ctrl_op_ctx: Mutex::new(HashMap::new()),
            revc_pkt_map: RecvPktMap::new(0, 0),
            check_recv_pkt_comp_thread: OnceLock::new(),
            adaptor: HardwareDevice::init().map_err(Error::Device)?,
        });

        let dev = Self(inner);

        let dev_for_poll_ctrl_rb = dev.clone();
        let dev_for_poll_work_rb = dev.clone();
        let dev_for_check_recv_pkt_comp = dev.clone();

        thread::spawn(move || dev_for_poll_ctrl_rb.poll_ctrl_rb());
        thread::spawn(move || dev_for_poll_work_rb.poll_work_rb());
        thread::spawn(move || dev_for_check_recv_pkt_comp.check_recv_pkt_comp());

        Ok(dev)
    }

    pub fn new_software() -> Result<Self, Error> {
        let inner = Arc::new(DeviceInner {
            is_hardware: false,
            pd: Mutex::new(HashMap::new()),
            mr_table: Mutex::new([Self::MR_TABLE_EMPTY_ELEM; MR_TABLE_SIZE]),
            qp: Mutex::new(HashMap::new()),
            mr_pgt: Mutex::new(MrPgt::new()),
            ctrl_op_ctx: Mutex::new(HashMap::new()),
            send_op_ctx: Mutex::new(HashMap::new()),
            recv_op_ctx: Mutex::new(HashMap::new()),
            revc_pkt_map: RecvPktMap::new(0, 0),
            check_recv_pkt_comp_thread: OnceLock::new(),
            adaptor: SoftwareDevice::init().map_err(Error::Device)?,
        });

        let dev = Self(inner);

        let dev_for_poll_ctrl_rb = dev.clone();
        let dev_for_poll_work_rb = dev.clone();
        let dev_for_check_recv_pkt_comp = dev.clone();

        thread::spawn(move || dev_for_poll_ctrl_rb.poll_ctrl_rb());
        thread::spawn(move || dev_for_poll_work_rb.poll_work_rb());
        thread::spawn(move || dev_for_check_recv_pkt_comp.check_recv_pkt_comp());

        Ok(dev)
    }

    pub fn new_emulated(server_port: u16, heap_mem_start_addr: usize) -> Result<Self, Error> {
        let inner = Arc::new(DeviceInner {
            is_hardware: false,
            pd: Mutex::new(HashMap::new()),
            mr_table: Mutex::new([Self::MR_TABLE_EMPTY_ELEM; MR_TABLE_SIZE]),
            qp: Mutex::new(HashMap::new()),
            mr_pgt: Mutex::new(MrPgt::new()),
            ctrl_op_ctx: Mutex::new(HashMap::new()),
            send_op_ctx: Mutex::new(HashMap::new()),
            recv_op_ctx: Mutex::new(HashMap::new()),
            revc_pkt_map: RecvPktMap::new(0, 0),
            check_recv_pkt_comp_thread: OnceLock::new(),
            adaptor: EmulatedDevice::init(server_port, heap_mem_start_addr)
                .map_err(Error::Device)?,
        });

        let dev = Self(inner);

        let dev_for_poll_ctrl_rb = dev.clone();
        let dev_for_poll_work_rb = dev.clone();
        let dev_for_check_recv_pkt_comp = dev.clone();

        thread::spawn(move || dev_for_poll_ctrl_rb.poll_ctrl_rb());
        thread::spawn(move || dev_for_poll_work_rb.poll_work_rb());
        thread::spawn(move || dev_for_check_recv_pkt_comp.check_recv_pkt_comp());

        Ok(dev)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn send_data(
        &self,
        qp: Qp,
        dqp_ip: Ipv4Addr,
        mac_addr: [u8; 6],
        dqpn: u32,
        raddr: u64,
        rkey: [u8; 4],
        flags: u8,
        sgl: Vec<ScatterGatherElement>,
    ) -> Result<(), Error> {
        let psn = self
            .0
            .qp
            .lock()
            .unwrap()
            .get(&qp)
            .ok_or(Error::InvalidQp)?
            .send_psn;

        let desc_header = ToCardWorkRbDescCommonHeader {
            valid: true,
            opcode: ToCardWorkRbDescOpcode::Send,
            is_last: true,
            is_first: true,
            extra_segment_cnt: 0,
            is_success_or_need_signal_cplt: false,
            total_len: sgl.iter().fold(0, |acc, elem| acc + elem.len),
        };

        let desc = ToCardWorkRbDesc::Request(ToCardWorkRbDescRequest {
            common_header: desc_header,
            raddr,
            rkey,
            dqp_ip,
            pmtu: qp.pmtu.clone(),
            flags,
            qp_type: qp.qp_type.clone(),
            sge_cnt: sgl.len() as u8,
            psn, // TODO: calculate psn
            mac_addr,
            dqpn,
            imm: [0; 4],
            sgl: DeviceScatterGatherList::from(sgl),
        });

        // save operation context for unparking
        {
            let mut ctx = self.0.send_op_ctx.lock().unwrap();

            match ctx.entry(qp.clone()) {
                Entry::Occupied(_) => return Err(Error::QpBusy),
                Entry::Vacant(entry) => {
                    entry.insert(SendOpCtx {
                        thread: thread::current(),
                        result: None,
                    });
                }
            }
        }

        // send desc to device
        self.0
            .adaptor
            .to_card_work_rb()
            .push(desc)
            .map_err(|_| Error::DeviceBusy)?;

        // park and wait
        thread::park();

        // unparked and poll result
        let SendOpCtx {
            thread: _,
            result: Some(result),
        } = (loop {
            let mut ctx = self.0.send_op_ctx.lock().unwrap();

            match ctx.get(&qp) {
                Some(SendOpCtx {
                    thread: _,
                    result: Some(_),
                }) => {}
                Some(SendOpCtx {
                    thread: _,
                    result: None,
                }) => continue,
                None => return Err(Error::SendCtxLost),
            }

            break ctx.remove(&qp).unwrap();
        })
        else {
            unreachable!()
        };

        if !result {
            return Err(Error::DeviceReturnFailed);
        }

        // TODO: update send_psn

        Ok(())
    }

    pub fn recv_data(
        &self,
        qp: Qp,
        dqp_ip: Ipv4Addr,
        mac_addr: [u8; 6],
        dqpn: u32,
        total_len: u32,
    ) -> Result<(), Error> {
        let psn = self
            .0
            .qp
            .lock()
            .unwrap()
            .get(&qp)
            .ok_or(Error::InvalidQp)?
            .recv_psn;

        {
            let mut ctx = self.0.recv_op_ctx.lock().unwrap();

            match ctx.entry(qp.clone()) {
                Entry::Occupied(_) => return Err(Error::QpBusy),
                Entry::Vacant(entry) => {
                    let pkt_map = unsafe {
                        (&self.0.revc_pkt_map as *const _ as *mut RecvPktMap)
                            .as_mut()
                            .unwrap_unchecked()
                    };

                    *pkt_map = RecvPktMap::new(total_len as usize, psn); // update recv pkt map

                    entry.insert(RecvOpCtx {
                        thread: thread::current(),
                        result: None,
                    });
                }
            }
        }

        self.0.check_recv_pkt_comp_thread.get().unwrap().unpark();
        thread::park();

        let RecvOpCtx {
            thread: _,
            result: Some(result),
        } = (loop {
            let mut ctx = self.0.recv_op_ctx.lock().unwrap();

            match ctx.get(&qp) {
                Some(RecvOpCtx {
                    thread: _,
                    result: Some(_),
                }) => {}
                Some(RecvOpCtx {
                    thread: _,
                    result: None,
                }) => continue,
                None => return Err(Error::RecvCtxLost),
            }

            break ctx.remove(&qp).unwrap();
        })
        else {
            unreachable!()
        };

        if !result {
            return Err(Error::DeviceReturnFailed);
        }

        let bth_pkey = [0; 2]; // TODO: get pkey
        let bth_tver_pad_m_se = 0b00000000;
        let bth_opcode = 0b00010001; // ACK
        let bth_dqp = dqpn.to_le_bytes();
        let bth_resv8 = 0;
        let bth_psn = psn.to_le_bytes();
        let bth_resv7_a = 0;
        let aeth_msn = psn.to_le_bytes(); // TODO: update msn
        let aeth_syn = 0;

        let ack_pkt = [
            // BTH bytes 0-3
            bth_pkey[0],
            bth_pkey[1],
            bth_tver_pad_m_se,
            bth_opcode,
            // BTH bytes 4-7
            bth_dqp[0],
            bth_dqp[1],
            bth_dqp[2],
            bth_resv8,
            // BTH bytes 8-11
            bth_psn[0],
            bth_psn[1],
            bth_psn[2],
            bth_resv7_a,
            // AETH bytes 0-3
            aeth_msn[0],
            aeth_msn[1],
            aeth_msn[2],
            aeth_syn,
        ];

        let mr = self.reg_mr(
            qp.pd.clone(),
            ack_pkt.as_ptr() as u64,
            ack_pkt.len() as u32,
            4096,
            0,
        )?;

        let sgl = vec![ScatterGatherElement {
            laddr: ack_pkt.as_ptr() as u64,
            lkey: mr.key.to_le_bytes(),
            len: ack_pkt.len() as u32,
        }];

        let desc_header = ToCardWorkRbDescCommonHeader {
            valid: true,
            opcode: ToCardWorkRbDescOpcode::Send,
            is_last: true,
            is_first: true,
            extra_segment_cnt: 0,
            is_success_or_need_signal_cplt: false,
            total_len: ack_pkt.len() as u32,
        };

        let desc = ToCardWorkRbDesc::Request(ToCardWorkRbDescRequest {
            common_header: desc_header,
            raddr: 0,
            rkey: [0; 4],
            dqp_ip,
            pmtu: qp.pmtu.clone(),
            flags: 0,
            qp_type: DeviceQpType::RawPacket,
            sge_cnt: sgl.len() as u8,
            psn: 0,
            mac_addr,
            dqpn,
            imm: [0; 4],
            sgl: DeviceScatterGatherList::from(sgl),
        });

        self.0
            .adaptor
            .to_card_work_rb()
            .push(desc)
            .map_err(|_| Error::DeviceBusy)?;

        // TODO: update recv_psn

        Ok(())
    }

    fn do_ctrl_op(&self, id: [u8; 4], desc: ToCardCtrlRbDesc) -> Result<bool, Error> {
        // save operation context for unparking
        {
            let mut ctx = self.0.ctrl_op_ctx.lock().unwrap();

            let old = ctx.insert(
                id,
                CtrlOpCtx {
                    thread: thread::current(),
                    result: None,
                },
            );

            assert!(old.is_none());
        }

        // send desc to device
        self.0
            .adaptor
            .to_card_ctrl_rb()
            .push(desc)
            .map_err(|_| Error::DeviceBusy)?;

        // park and wait
        thread::park();

        // unparked and poll result
        let CtrlOpCtx {
            thread: _,
            result: Some(result),
        } = (loop {
            let mut ctx = self.0.ctrl_op_ctx.lock().unwrap();

            match ctx.get(&id) {
                Some(CtrlOpCtx {
                    thread: _,
                    result: Some(_),
                }) => {}
                Some(CtrlOpCtx {
                    thread: _,
                    result: None,
                }) => continue,
                None => return Err(Error::CtrlCtxLost),
            }

            break ctx.remove(&id).unwrap();
        })
        else {
            unreachable!()
        };

        Ok(result)
    }

    fn check_recv_pkt_comp(self) {
        self.0
            .check_recv_pkt_comp_thread
            .set(thread::current())
            .unwrap();

        loop {
            thread::park(); //park and wait for new recv op

            loop {
                if self.0.revc_pkt_map.is_complete() {
                    break;
                }

                thread::sleep(Duration::from_micros(100));
            }

            let mut ctx_map = self.0.recv_op_ctx.lock().unwrap();

            let Some((_, ctx)) = ctx_map.iter_mut().next() else {
                eprintln!("no send ctx found");
                continue;
            };

            ctx.result = Some(true);
            ctx.thread.unpark();
        }
    }
}

impl RecvPktMap {
    const FULL_CHUNK_DIV_BIT_SHIFT_CNT: u32 = 64usize.ilog2();
    const LAST_CHUNK_MOD_MASK: usize = mem::size_of::<u64>() * 8 - 1;

    fn new(len: usize, start_psn: u32) -> Self {
        let create_stage = |len| {
            // used-bit count in the last u64, len % 64
            let rem = len & Self::LAST_CHUNK_MOD_MASK;
            // number of u64, ceil(len / 64)
            let len = (len >> Self::FULL_CHUNK_DIV_BIT_SHIFT_CNT) + (rem != 0) as usize;
            // last u64, lower `rem` bits are 1, higher bits are 0. if `rem == 0``, all bits are 1
            let last_chunk = ((1u64 << rem) - 1) | ((rem != 0) as u64).wrapping_sub(1);

            (vec![0; len].into_boxed_slice(), last_chunk)
        };

        let (stage_0, stage_0_last_chunk) = create_stage(len);
        let (stage_1, stage_1_last_chunk) = create_stage(stage_0.len());
        let (stage_2, stage_2_last_chunk) = create_stage(stage_1.len());

        Self {
            start_psn,
            stage_0,
            stage_0_last_chunk,
            stage_1,
            stage_1_last_chunk,
            stage_2,
            stage_2_last_chunk,
        }
    }

    fn insert(&mut self, psn: u32) {
        let psn = (psn - self.start_psn) as usize;

        let stage_0_idx = psn >> Self::FULL_CHUNK_DIV_BIT_SHIFT_CNT; // which u64 in stage 0
        let stage_0_rem = psn & Self::LAST_CHUNK_MOD_MASK; // bit position in u64
        let stage_0_bit = 1 << stage_0_rem; // bit mask
        self.stage_0[stage_0_idx] |= stage_0_bit; // set bit in stage 0

        let is_stage_0_last_chunk = stage_0_idx == self.stage_0.len() - 1; // is the bit in the last u64 in stage 0
        let stage_0_chunk_expected =
            (is_stage_0_last_chunk as u64).wrapping_sub(1) | self.stage_0_last_chunk; // expected bit mask of the target u64 in stage 0
        let is_stage_0_chunk_complete = self.stage_0[stage_0_idx] == stage_0_chunk_expected; // is the target u64 in stage 0 full

        let stage_1_idx = stage_0_idx >> Self::FULL_CHUNK_DIV_BIT_SHIFT_CNT; // which u64 in stage 1
        let stage_1_rem = stage_0_idx & Self::LAST_CHUNK_MOD_MASK; // bit position in u64
        let stage_1_bit = (is_stage_0_chunk_complete as u64) << stage_1_rem; // bit mask
        self.stage_1[stage_1_idx] |= stage_1_bit; // set bit in stage 1

        let is_stage_1_last_chunk = stage_1_idx == self.stage_1.len() - 1; // is the bit in the last u64 in stage 1
        let stage_1_chunk_expected =
            (is_stage_1_last_chunk as u64).wrapping_sub(1) | self.stage_1_last_chunk; // expected bit mask of the target u64 in stage 1
        let is_stage_1_chunk_complete = self.stage_1[stage_1_idx] == stage_1_chunk_expected; // is the target u64 in stage 1 full

        let stage_2_idx = stage_1_idx >> Self::FULL_CHUNK_DIV_BIT_SHIFT_CNT; // which u64 in stage 2
        let stage_2_rem = stage_1_idx & Self::LAST_CHUNK_MOD_MASK; // bit position in u64
        let stage_2_bit = (is_stage_1_chunk_complete as u64) << stage_2_rem; // bit mask
        self.stage_2[stage_2_idx] |= stage_2_bit; // set bit in stage 2
    }

    fn is_complete(&self) -> bool {
        self.stage_2
            .iter()
            .enumerate()
            .fold(true, |acc, (idx, &bits)| {
                let is_last_chunk = idx == self.stage_2.len() - 1;
                let chunk_expected =
                    (is_last_chunk as u64).wrapping_sub(1) | self.stage_2_last_chunk;
                let is_chunk_complete = bits == chunk_expected;
                acc && is_chunk_complete
            })
    }

    fn _check_missing(&self) -> MissingPkt {
        MissingPkt { map: self }
    }
}

fn get_ctrl_op_id() -> [u8; 4] {
    // TODO: make id unique between different processes
    NEXT_CTRL_OP_ID.fetch_add(1, Ordering::AcqRel).to_le_bytes()
}

impl Iterator for MissingPkt<'_> {
    type Item = Range<u32>;

    fn next(&mut self) -> Option<Self::Item> {
        todo!()
    }
}

impl From<Vec<ScatterGatherElement>> for DeviceScatterGatherList {
    fn from(sgl: Vec<ScatterGatherElement>) -> Self {
        let data = array::from_fn(|idx| DeviceScatterGatherElement {
            laddr: sgl.get(idx).map_or(0, |elem| elem.laddr),
            lkey: sgl.get(idx).map_or([0; 4], |elem| elem.lkey),
            len: sgl.get(idx).map_or(0, |elem| elem.len),
        });

        Self {
            data,
            len: sgl.len() as u32,
        }
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Device(Box<dyn StdError>),
    #[error("device busy")]
    DeviceBusy,
    #[error("device return failed")]
    DeviceReturnFailed,
    #[error("ongoing ctrl cmd ctx lost")]
    CtrlCtxLost,
    #[error("ongoing send ctx lost")]
    SendCtxLost,
    #[error("ongoing recv ctx lost")]
    RecvCtxLost,
    #[error("QP busy")]
    QpBusy,
    #[error("invalid PD handle")]
    InvalidPd,
    #[error("invalid MR handle")]
    InvalidMr,
    #[error("invalid QP handle")]
    InvalidQp,
    #[error("PD in use")]
    PdInUse,
    #[error("QP in use")]
    QpInUse,
    #[error("no available QP")]
    NoAvailableQp,
    #[error("no available MR")]
    NoAvailableMr,
    #[error("allocate page table failed")]
    AllocPageTable,
}
