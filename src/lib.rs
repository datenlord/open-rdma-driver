use crate::{
    device::{
        DeviceAdaptor, EmulatedDevice, HardwareDevice,
        ScatterGatherElement as DeviceScatterGatherElement,
        ScatterGatherList as DeviceScatterGatherList, ToCardCtrlRbDesc, ToCardWorkRbDesc,
        ToCardWorkRbDescCommonHeader, ToCardWorkRbDescOpcode, ToCardWorkRbDescRequest,
    },
    mr::MrCtx,
    pd::PdCtx,
    qp::QpCtx,
};
use std::{
    array,
    collections::{hash_map::Entry, HashMap},
    error::Error as StdError,
    net::Ipv4Addr,
    ops::Range,
    sync::{Arc, Mutex},
    thread::{self, Thread},
};
use thiserror::Error;

mod device;
mod poll;

pub mod mr;
pub mod pd;
pub mod qp;

pub use crate::{mr::Mr, pd::Pd, qp::Qp};

#[derive(Clone)]
pub struct Device(Arc<DeviceInner<dyn DeviceAdaptor>>);

struct DeviceInner<D: ?Sized> {
    #[allow(unused)]
    is_emulated: bool,
    pd: Mutex<HashMap<Pd, PdCtx>>,
    mr: Mutex<HashMap<Mr, MrCtx>>,
    qp: Mutex<HashMap<Qp, QpCtx>>,
    ctrl_op_ctx: Mutex<HashMap<[u8; 4], CtrlOpCtx>>,
    send_op_ctx: Mutex<HashMap<Qp, SendOpCtx>>,
    recv_op_ctx: Mutex<HashMap<Qp, RecvOpCtx>>,
    revc_pkt_map: RecvPktMap, // TODO: extend to support multiple QPs
    adaptor: D,
}

pub struct ScatterGatherElement {
    laddr: u64,
    lkey: [u8; 4],
    len: u32,
}

struct CtrlOpCtx {
    #[allow(unused)]
    thread: Thread,
    result: Option<bool>,
}

struct SendOpCtx {
    #[allow(unused)]
    thread: Thread,
    result: Option<bool>,
}

struct RecvOpCtx {
    #[allow(unused)]
    thread: Thread,
    result: Option<bool>,
}

#[allow(unused)]
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
#[allow(unused)]
struct MissingPkt<'a> {
    map: &'a RecvPktMap,
}

impl Device {
    pub fn new_emulated() -> Result<Self, Error> {
        let inner = Arc::new(DeviceInner {
            is_emulated: true,
            pd: Mutex::new(HashMap::new()),
            mr: Mutex::new(HashMap::new()),
            qp: Mutex::new(HashMap::new()),
            ctrl_op_ctx: Mutex::new(HashMap::new()),
            send_op_ctx: Mutex::new(HashMap::new()),
            recv_op_ctx: Mutex::new(HashMap::new()),
            revc_pkt_map: RecvPktMap::new(0, 0),
            adaptor: EmulatedDevice::init().map_err(Error::Device)?,
        });

        let dev = Self(inner);

        let dev_for_poll_ctrl_rb = dev.clone();
        let dev_for_poll_work_rb = dev.clone();

        thread::spawn(move || dev_for_poll_ctrl_rb.poll_ctrl_rb());
        thread::spawn(move || dev_for_poll_work_rb.poll_work_rb());

        Ok(dev)
    }

    pub fn new_hardware() -> Result<Self, Error> {
        let inner = Arc::new(DeviceInner {
            is_emulated: false,
            pd: Mutex::new(HashMap::new()),
            mr: Mutex::new(HashMap::new()),
            qp: Mutex::new(HashMap::new()),
            send_op_ctx: Mutex::new(HashMap::new()),
            recv_op_ctx: Mutex::new(HashMap::new()),
            ctrl_op_ctx: Mutex::new(HashMap::new()),
            revc_pkt_map: RecvPktMap::new(0, 0),
            adaptor: HardwareDevice::init().map_err(Error::Device)?,
        });

        let dev = Self(inner);

        let dev_for_poll_ctrl_rb = dev.clone();
        let dev_for_poll_work_rb = dev.clone();

        thread::spawn(move || dev_for_poll_ctrl_rb.poll_ctrl_rb());
        thread::spawn(move || dev_for_poll_work_rb.poll_work_rb());

        Ok(dev)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn send(
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
            psn,
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

    pub fn recv(&self, qp: Qp, total_len: u32) -> Result<(), Error> {
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
}

impl RecvPktMap {
    fn new(len: usize, start_psn: u32) -> Self {
        fn create_stage(len: usize) -> (Box<[u64]>, u64) {
            // used-bit count in the last u64, len % 64
            let rem = len & 63;
            // number of u64, ceil(len / 64)
            let len = (len >> 6) + (rem != 0) as usize;
            // last u64, lower `rem` bits are 1, higher bits are 0. if `rem == 0``, all bits are 1
            let last_chunk = ((1u64 << rem) - 1) | ((rem != 0) as u64).wrapping_sub(1);

            (vec![0; len].into_boxed_slice(), last_chunk)
        }

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

    fn _insert(&mut self, psn: u32) {
        let psn = (psn - self.start_psn) as usize;

        let stage_0_idx = psn >> 6; // which u64 in stage 0
        let stage_0_rem = psn & 63; // bit position in u64
        let stage_0_bit = 1 << stage_0_rem; // bit mask
        self.stage_0[stage_0_idx] |= stage_0_bit; // set bit in stage 0

        let is_stage_0_last_chunk = stage_0_idx == self.stage_0.len() - 1; // is the bit in the last u64 in stage 0
        let stage_0_chunk_expected =
            (is_stage_0_last_chunk as u64).wrapping_sub(1) | self.stage_0_last_chunk; // expected bit mask of the target u64 in stage 0
        let is_stage_0_chunk_full = self.stage_0[stage_0_idx] == stage_0_chunk_expected; // is the target u64 in stage 0 full

        let stage_1_idx = stage_0_idx >> 6; // which u64 in stage 1
        let stage_1_rem = stage_0_idx & 63; // bit position in u64
        let stage_1_bit = (is_stage_0_chunk_full as u64) << stage_1_rem; // bit mask
        self.stage_1[stage_1_idx] |= stage_1_bit; // set bit in stage 1

        let is_stage_1_last_chunk = stage_1_idx == self.stage_1.len() - 1; // is the bit in the last u64 in stage 1
        let stage_1_chunk_expected =
            (is_stage_1_last_chunk as u64).wrapping_sub(1) | self.stage_1_last_chunk; // expected bit mask of the target u64 in stage 1
        let is_stage_1_chunk_full = self.stage_1[stage_1_idx] == stage_1_chunk_expected; // is the target u64 in stage 1 full

        let stage_2_idx = stage_1_idx >> 6; // which u64 in stage 2
        let stage_2_rem = stage_1_idx & 63; // bit position in u64
        let stage_2_bit = (is_stage_1_chunk_full as u64) << stage_2_rem; // bit mask
        self.stage_2[stage_2_idx] |= stage_2_bit; // set bit in stage 2
    }

    fn _is_complete(&self) -> bool {
        self.stage_2
            .iter()
            .enumerate()
            .fold(true, |acc, (idx, &bits)| {
                let is_last_chunk = idx == self.stage_2.len() - 1;
                let chunk_expected =
                    (is_last_chunk as u64).wrapping_sub(1) | self.stage_2_last_chunk;
                let is_chunk_full = bits == chunk_expected;
                acc && is_chunk_full
            })
    }

    fn _check_missing(&self) -> MissingPkt {
        MissingPkt { map: self }
    }
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
}
