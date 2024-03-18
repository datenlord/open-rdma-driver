use crate::{
    device::{
        DeviceAdaptor, EmulatedDevice, HardwareDevice, SoftwareDevice, ToCardCtrlRbDesc,
        ToCardWorkRbDescCommon,
    },
    mr::{MrCtx, MrPgt},
    pd::PdCtx,
};
use device::{ToCardCtrlRbDescSge, ToCardWorkRbDescBuilder};
use pkt_checker::PacketChecker;
use poll::work::WorkDescPoller;
use qp::QpContext;
use recv_pkt_map::RecvPktMap;
use responser::{DescResponser, WorkDescriptorSender};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, AtomicU32, Ordering}, Arc, Mutex, OnceLock, RwLock,
    },
    thread::{self, Thread},
};
use types::{Key, MemAccessTypeFlag, Psn, Qpn};
use utils::calculate_packet_cnt;

pub mod mr;
pub mod pd;
pub mod qp;
pub mod types;

mod device;
mod poll;
mod recv_pkt_map;
mod pkt_checker;
mod responser;
mod utils;

pub use crate::{mr::Mr, pd::Pd, qp::Qp};
pub use types::Error;

const MR_KEY_IDX_BIT_CNT: usize = 8;
const MR_TABLE_SIZE: usize = 64;
const MR_PGT_SIZE: usize = 1024;
const QP_MAX_CNT: usize = 1024;

#[derive(Clone)]
pub struct Device(Arc<DeviceInner<dyn DeviceAdaptor>>);

struct DeviceInner<D: ?Sized> {
    pd: Mutex<HashMap<Pd, PdCtx>>,
    mr_table: Mutex<[Option<MrCtx>; MR_TABLE_SIZE]>,
    qp_table: Arc<RwLock<HashMap<Qpn, QpContext>>>,
    mr_pgt: Mutex<MrPgt>,
    ctrl_op_ctx: Mutex<HashMap<u32, CtrlOpCtx>>,
    next_ctrl_op_id: AtomicU32,
    qp_availability: Box<[AtomicBool]>,
    responser: OnceLock<DescResponser>,
    work_desc_poller : OnceLock<WorkDescPoller>,
    pkt_checker_thread : OnceLock<PacketChecker>,
    adaptor: D,
}

pub struct Sge {
    pub addr: u64,
    pub len: u32,
    pub key: Key,
}

struct CtrlOpCtx {
    thread: Thread,
    result: Option<bool>,
}

struct WriteOpCtx {
    thread: Thread,
    result: Option<bool>,
}

impl Device {
    const MR_TABLE_EMPTY_ELEM: Option<MrCtx> = None;

    pub fn new_hardware() -> Result<Self, Error> {
        let qp_table = Arc::new(RwLock::new(HashMap::new()));
        let qp_availability: Vec<AtomicBool> =
            (0..QP_MAX_CNT).map(|_| AtomicBool::new(true)).collect();

        // by IB spec, QP0 and QP1 are reserved, so qpn should start with 2
        qp_availability[0].store(false, Ordering::Relaxed);
        qp_availability[1].store(false, Ordering::Relaxed);

        let inner = Arc::new(DeviceInner {
            pd: Mutex::new(HashMap::new()),
            mr_table: Mutex::new([Self::MR_TABLE_EMPTY_ELEM; MR_TABLE_SIZE]),
            qp_table: qp_table.clone(),
            mr_pgt: Mutex::new(MrPgt::new()),
            // read_op_ctx: Mutex::new(HashMap::new()),
            ctrl_op_ctx: Mutex::new(HashMap::new()),
            next_ctrl_op_id: AtomicU32::new(0),
            qp_availability: qp_availability.into_boxed_slice(),
            adaptor: HardwareDevice::init().map_err(Error::Device)?,
            responser: OnceLock::new(),
            pkt_checker_thread : OnceLock::new(),
            work_desc_poller : OnceLock::new(),
        });

        let dev = Self(inner);
        dev.init()?;

        Ok(dev)
    }

    pub fn new_software() -> Result<Self, Error> {
        let qp_table = Arc::new(RwLock::new(HashMap::new()));
        let qp_availability: Vec<AtomicBool> =
            (0..QP_MAX_CNT).map(|_| AtomicBool::new(true)).collect();

        // by IB spec, QP0 and QP1 are reserved, so qpn should start with 2
        qp_availability[0].store(false, Ordering::Relaxed);
        qp_availability[1].store(false, Ordering::Relaxed);

        let inner = Arc::new(DeviceInner {
            pd: Mutex::new(HashMap::new()),
            mr_table: Mutex::new([Self::MR_TABLE_EMPTY_ELEM; MR_TABLE_SIZE]),
            qp_table: qp_table.clone(),
            mr_pgt: Mutex::new(MrPgt::new()),
            ctrl_op_ctx: Mutex::new(HashMap::new()),
            next_ctrl_op_id: AtomicU32::new(0),
            qp_availability: qp_availability.into_boxed_slice(),
            responser: OnceLock::new(),
            work_desc_poller : OnceLock::new(),
            pkt_checker_thread : OnceLock::new(),
            adaptor: SoftwareDevice::init().map_err(Error::Device)?,
        });

        let dev = Self(inner);
        dev.init()?;

        Ok(dev)
    }

    pub fn new_emulated(
        rpc_server_addr: SocketAddr,
        heap_mem_start_addr: usize,
    ) -> Result<Self, Error> {
        let qp_table = Arc::new(RwLock::new(HashMap::new()));
        let qp_availability: Vec<AtomicBool> =
            (0..QP_MAX_CNT).map(|_| AtomicBool::new(true)).collect();

        // by IB spec, QP0 and QP1 are reserved, so qpn should start with 2
        qp_availability[0].store(false, Ordering::Relaxed);
        qp_availability[1].store(false, Ordering::Relaxed);

        let inner = Arc::new(DeviceInner {
            pd: Mutex::new(HashMap::new()),
            mr_table: Mutex::new([Self::MR_TABLE_EMPTY_ELEM; MR_TABLE_SIZE]),
            qp_table: qp_table.clone(),
            mr_pgt: Mutex::new(MrPgt::new()),
            ctrl_op_ctx: Mutex::new(HashMap::new()),
            next_ctrl_op_id: AtomicU32::new(0),
            qp_availability: qp_availability.into_boxed_slice(),
            responser: OnceLock::new(),
            work_desc_poller : OnceLock::new(),
            pkt_checker_thread : OnceLock::new(),
            adaptor: EmulatedDevice::init(rpc_server_addr, heap_mem_start_addr)
                .map_err(Error::Device)?,
        });

        let dev = Self(inner);

        dev.init()?;

        Ok(dev)
    }

    pub fn read(
        &self,
        qpn: Qpn,
        raddr: u64,
        rkey: Key,
        flags: MemAccessTypeFlag,
        sge: Sge,
    ) -> Result<(), Error> {
        let common = {
            let qp_table = self.0.qp_table.read().unwrap();
            let qp = qp_table.get(&qpn).ok_or(Error::InvalidQp)?;

            let total_len = sge.len;
            let mut common = ToCardWorkRbDescCommon {
                total_len,
                raddr,
                rkey,
                dqp_ip: qp.dqp_ip,
                dqpn: qpn,
                mac_addr: qp.mac_addr,
                pmtu: qp.pmtu.clone(),
                flags,
                qp_type: qp.qp_type,
                psn: Psn::default(),
            };
            let send_psn = &mut qp.inner.lock().unwrap().send_psn;
            common.psn = *send_psn;
            let packet_cnt = calculate_packet_cnt(qp.pmtu.clone(), raddr, total_len);
            *send_psn = send_psn.wrapping_add(packet_cnt);
            common
        };

        let builder = ToCardWorkRbDescBuilder::new_read()
            .with_common(common)
            .with_sge(sge);
        self.send_work_desc(builder)?;

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn write(
        &self,
        qpn: Qpn,
        raddr: u64,
        rkey: Key,
        flags: MemAccessTypeFlag,
        sge0: Sge,
        sge1: Option<Sge>,
        sge2: Option<Sge>,
        sge3: Option<Sge>,
    ) -> Result<(), Error> {
        let common = {
            let qp_table = self.0.qp_table.read().unwrap();
            let qp = qp_table.get(&qpn).ok_or(Error::InvalidQp)?;
            let total_len = sge0.len
                + sge1.as_ref().map_or(0, |sge| sge.len)
                + sge2.as_ref().map_or(0, |sge| sge.len)
                + sge3.as_ref().map_or(0, |sge| sge.len);
            let mut common = ToCardWorkRbDescCommon {
                total_len,
                raddr,
                rkey,
                dqp_ip: qp.dqp_ip,
                dqpn: qpn,
                mac_addr: qp.mac_addr,
                pmtu: qp.pmtu.clone(),
                flags,
                qp_type: qp.qp_type,
                psn: Psn::default(),
            };

            let send_psn = &mut qp.inner.lock().unwrap().send_psn;
            common.psn = *send_psn;
            let packet_cnt = calculate_packet_cnt(qp.pmtu.clone(), raddr, total_len);
            send_psn.wrapping_add(packet_cnt);
            common
        };

        let builder = ToCardWorkRbDescBuilder::new_write()
            .with_common(common)
            .with_sge(sge0)
            .with_option_sge(sge1)
            .with_option_sge(sge2)
            .with_option_sge(sge3);

        self.send_work_desc(builder)?;

        Ok(())
    }

    fn do_ctrl_op(&self, id: u32, desc: ToCardCtrlRbDesc) -> Result<bool, Error> {
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

    fn get_ctrl_op_id(&self) -> u32 {
        self.0.next_ctrl_op_id.fetch_add(1, Ordering::AcqRel)
    }

    fn init(&self) -> Result<(), Error> {
        let (send_queue, rece_queue) = std::sync::mpsc::channel();
        let ack_buf = self.init_ack_buf()?;
        let responser = DescResponser::new(
            Arc::new(self.clone()),
            rece_queue,
            ack_buf,
            self.0.qp_table.clone(),
        );
        if self.0.responser.set(responser).is_err() {
            panic!("responser has been set");
        }

        let dev_for_poll_ctrl_rb = self.clone();
        let recv_pkt_map = Arc::new(RwLock::new(HashMap::new()));
        let work_desc_poller = WorkDescPoller::new(
            self.0.adaptor.to_host_work_rb(),
            recv_pkt_map.clone(),
            self.0.qp_table.clone(),
            send_queue.clone(),
        );
        if self.0.work_desc_poller.set(work_desc_poller).is_err(){
            panic!("work_desc_poller has been set");
        }
        let pkt_checker_thread = PacketChecker::new(send_queue, recv_pkt_map);
        if self.0.pkt_checker_thread.set(pkt_checker_thread).is_err(){
            panic!("pkt_checker_thread has been set");
        }
        
        thread::spawn(move || dev_for_poll_ctrl_rb.poll_ctrl_rb());
        Ok(())
    }
}

impl From<Sge> for ToCardCtrlRbDescSge {
    fn from(sge: Sge) -> Self {
        Self {
            addr: sge.addr,
            len: sge.len,
            key: sge.key,
        }
    }
}

impl WorkDescriptorSender for Device {
    fn send_work_desc(&self, desc_builder: ToCardWorkRbDescBuilder) -> Result<(), Error> {
        let desc = desc_builder.build()?;
        self.0
            .adaptor
            .to_card_work_rb()
            .push(desc)
            .map_err(|_| Error::DeviceBusy)?;
        Ok(())
    }
}
