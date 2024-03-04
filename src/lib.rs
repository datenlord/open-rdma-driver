use crate::{
    device::{
        DeviceAdaptor, EmulatedDevice, HardwareDevice, SoftwareDevice, ToCardCtrlRbDesc,
        ToCardCtrlRbDescSge as DeviceSge, ToCardWorkRbDesc, ToCardWorkRbDescCommon,
        ToCardWorkRbDescWrite,
    },
    mr::{MrCtx, MrPgt},
    pd::PdCtx,
    qp::QpCtx,
};
use device::QpType;
use std::{
    collections::{hash_map::Entry, HashMap},
    error::Error as StdError,
    mem,
    net::SocketAddr,
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
    pd: Mutex<HashMap<Pd, PdCtx>>,
    mr_table: Mutex<[Option<MrCtx>; MR_TABLE_SIZE]>,
    qp: Mutex<HashMap<Qp, QpCtx>>,
    mr_pgt: Mutex<MrPgt>,
    ctrl_op_ctx: Mutex<HashMap<[u8; 4], CtrlOpCtx>>,
    send_op_ctx: Mutex<HashMap<Qp, SendOpCtx>>,
    revc_pkt_map: RecvPktMap, // TODO: extend to support multiple QPs
    check_recv_pkt_comp_thread: OnceLock<Thread>,
    adaptor: D,
}

pub struct Sge {
    pub addr: u64,
    pub len: u32,
    pub key: u32,
}

struct CtrlOpCtx {
    thread: Thread,
    result: Option<bool>,
}

struct SendOpCtx {
    thread: Thread,
    result: Option<bool>,
}

struct RecvPktMap {
    pkt_cnt: usize,
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
            pd: Mutex::new(HashMap::new()),
            mr_table: Mutex::new([Self::MR_TABLE_EMPTY_ELEM; MR_TABLE_SIZE]),
            qp: Mutex::new(HashMap::new()),
            mr_pgt: Mutex::new(MrPgt::new()),
            send_op_ctx: Mutex::new(HashMap::new()),
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
            pd: Mutex::new(HashMap::new()),
            mr_table: Mutex::new([Self::MR_TABLE_EMPTY_ELEM; MR_TABLE_SIZE]),
            qp: Mutex::new(HashMap::new()),
            mr_pgt: Mutex::new(MrPgt::new()),
            ctrl_op_ctx: Mutex::new(HashMap::new()),
            send_op_ctx: Mutex::new(HashMap::new()),
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

    pub fn new_emulated(
        rpc_server_addr: SocketAddr,
        heap_mem_start_addr: usize,
    ) -> Result<Self, Error> {
        let inner = Arc::new(DeviceInner {
            pd: Mutex::new(HashMap::new()),
            mr_table: Mutex::new([Self::MR_TABLE_EMPTY_ELEM; MR_TABLE_SIZE]),
            qp: Mutex::new(HashMap::new()),
            mr_pgt: Mutex::new(MrPgt::new()),
            ctrl_op_ctx: Mutex::new(HashMap::new()),
            send_op_ctx: Mutex::new(HashMap::new()),
            revc_pkt_map: RecvPktMap::new(0, 0),
            check_recv_pkt_comp_thread: OnceLock::new(),
            adaptor: EmulatedDevice::init(rpc_server_addr, heap_mem_start_addr)
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
    // TODO: discuess whether this function should be blocking?
    pub fn write(
        &self,
        qp: Qp,
        raddr: u64,
        rkey: u32,
        flags: u8,
        sge0: Sge,
        sge1: Option<Sge>,
        sge2: Option<Sge>,
        sge3: Option<Sge>,
    ) -> Result<(), Error> {
        let mut qp_table = self.0.qp.lock().unwrap();
        let qp_ctx = qp_table.get_mut(&qp).ok_or(Error::InvalidQp)?;

        let total_len = sge0.len
            + sge1.as_ref().map_or(0, |sge| sge.len)
            + sge2.as_ref().map_or(0, |sge| sge.len)
            + sge3.as_ref().map_or(0, |sge| sge.len);

        let desc = ToCardWorkRbDesc::Write(ToCardWorkRbDescWrite {
            common: ToCardWorkRbDescCommon {
                total_len,
                raddr,
                rkey,
                dqp_ip: qp.dqp_ip,
                dqpn: qp.dqpn,
                mac_addr: qp.mac_addr,
                pmtu: qp.pmtu.clone(),
                flags,
                qp_type: qp.qp_type.clone(),
                psn: qp_ctx.send_psn,
            },
            is_last: true,
            is_first: true,
            sge0: sge0.into(),
            sge1: sge1.map(|sge| sge.into()),
            sge2: sge2.map(|sge| sge.into()),
            sge3: sge3.map(|sge| sge.into()),
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

        drop(qp_table);

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

        let first_pkt_max_len = u64::from(&qp.pmtu) - (raddr % (u64::from(&qp.pmtu) - 1));

        let first_pkt_len = total_len.min(first_pkt_max_len as u32);
        let pkt_cnt = 1 + (total_len - first_pkt_len as u32).div_ceil(u64::from(&qp.pmtu) as u32);

        // regain the lock.
        // TODO: do we need to redesign the lock here?
        let mut qp_table = self.0.qp.lock().unwrap();
        let qp_ctx = qp_table.get_mut(&qp).ok_or(Error::InvalidQp)?;
        qp_ctx.send_psn += pkt_cnt;

        if !result {
            return Err(Error::DeviceReturnFailed);
        }

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

            // packet complete, send ack

            let mut qp_table = self.0.qp.lock().unwrap();
            let qp = qp_table.keys().next().unwrap(); // FIXME: Why call next to get a QP? too tricky?

            let bth_pkey = [0; 2]; // TODO: get pkey
            let bth_tver_pad_m_se = 0b00000000;
            let bth_opcode = 0b00010001; // ACK
            let bth_dqp = qp.dqpn.to_le_bytes();
            let bth_resv8 = 0;
            let bth_psn = [0; 3];
            let bth_resv7_a = 0;
            let aeth_msn = [0; 3];
            let aeth_syn = 0;
            let nreth = [0; 4];

            let ack_pkt = Box::new([
                // BTH bytes 0-3
                bth_opcode,
                bth_tver_pad_m_se,
                bth_pkey[1],
                bth_pkey[0],
                // BTH bytes 4-7
                bth_resv8,
                bth_dqp[2],
                bth_dqp[1],
                bth_dqp[0],
                // BTH bytes 8-11
                bth_resv7_a,
                bth_psn[2],
                bth_psn[1],
                bth_psn[0],
                // AETH bytes 0-3
                aeth_syn,
                aeth_msn[2],
                aeth_msn[1],
                aeth_msn[0],
                // NRETH bytes 0-3
                nreth[3],
                nreth[2],
                nreth[1],
                nreth[0],
            ]);

            // FIXME: Will this mr leak ?
            // FIXME: MR on stack? we don't know when hardware will consume this send request. allocate it on heap!
            // FIXME: use a pre-allocated MR as ack message pool.
            let ack_packet_len = ack_pkt.len();
            let ack_pkt_ptr = Box::into_raw(ack_pkt) as u64;
            let mr = self
                .reg_mr(
                    qp.pd.clone(),
                    ack_pkt_ptr,
                    ack_packet_len as u32,
                    2 * 1024 * 1024,
                    0,
                )
                .unwrap();

            let sge = Sge {
                addr: ack_pkt_ptr,
                len: ack_packet_len as u32,
                key: mr.key,
            };

            let desc = ToCardWorkRbDesc::Write(ToCardWorkRbDescWrite {
                common: ToCardWorkRbDescCommon {
                    total_len: sge.len,
                    raddr: 0,
                    rkey: 0,
                    dqp_ip: qp.dqp_ip,
                    dqpn: qp.dqpn,
                    mac_addr: qp.mac_addr,
                    pmtu: qp.pmtu.clone(),
                    flags: 0,
                    qp_type: QpType::RawPacket, // FIXME: this should be fixed to RawPacket?
                    psn: 0,
                },
                is_last: true,
                is_first: true,
                sge0: sge.into(),
                sge1: None,
                sge2: None,
                sge3: None,
            });

            self.0
                .adaptor
                .to_card_work_rb()
                .push(desc)
                .map_err(|_| Error::DeviceBusy)
                .unwrap();

            let qp_ctx = qp_table.values_mut().next().unwrap();
            qp_ctx.recv_psn += self.0.revc_pkt_map.pkt_cnt as u32;
        }
    }
}

impl RecvPktMap {
    const FULL_CHUNK_DIV_BIT_SHIFT_CNT: u32 = 64usize.ilog2();
    const LAST_CHUNK_MOD_MASK: usize = mem::size_of::<u64>() * 8 - 1;

    fn new(pkt_cnt: usize, start_psn: u32) -> Self {
        let create_stage = |len| {
            // used-bit count in the last u64, len % 64
            let rem = len & Self::LAST_CHUNK_MOD_MASK;
            // number of u64, ceil(len / 64)
            let len = (len >> Self::FULL_CHUNK_DIV_BIT_SHIFT_CNT) + (rem != 0) as usize;
            // last u64, lower `rem` bits are 1, higher bits are 0. if `rem == 0``, all bits are 1
            let last_chunk = ((1u64 << rem) - 1) | ((rem != 0) as u64).wrapping_sub(1);

            (vec![0; len].into_boxed_slice(), last_chunk)
        };

        let (stage_0, stage_0_last_chunk) = create_stage(pkt_cnt);
        let (stage_1, stage_1_last_chunk) = create_stage(stage_0.len());
        let (stage_2, stage_2_last_chunk) = create_stage(stage_1.len());

        Self {
            pkt_cnt,
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

impl From<Sge> for DeviceSge {
    fn from(sge: Sge) -> Self {
        Self {
            addr: sge.addr,
            len: sge.len,
            key: sge.key,
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
