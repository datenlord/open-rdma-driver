use crate::{
    device::{DeviceAdaptor, EmulatedDevice, HardwareDevice, ToCardCtrlRbDesc},
    mr::MrCtx,
    pd::PdCtx,
    qp::QpCtx,
};
use std::{
    collections::HashMap,
    error::Error as StdError,
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
    adaptor: D,
}

struct CtrlOpCtx {
    #[allow(unused)]
    thread: Thread,
    result: Option<bool>,
}

impl Device {
    pub fn new_emulated() -> Result<Self, Error> {
        let inner = Arc::new(DeviceInner {
            is_emulated: true,
            pd: Mutex::new(HashMap::new()),
            mr: Mutex::new(HashMap::new()),
            qp: Mutex::new(HashMap::new()),
            ctrl_op_ctx: Mutex::new(HashMap::new()),
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
            ctrl_op_ctx: Mutex::new(HashMap::new()),
            adaptor: HardwareDevice::init().map_err(Error::Device)?,
        });

        let dev = Self(inner);

        let dev_for_poll_ctrl_rb = dev.clone();
        let dev_for_poll_work_rb = dev.clone();

        thread::spawn(move || dev_for_poll_ctrl_rb.poll_ctrl_rb());
        thread::spawn(move || dev_for_poll_work_rb.poll_work_rb());

        Ok(dev)
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
    #[error("invalid PD handle")]
    InvalidPd,
    #[error("invalid MR handle")]
    InvalidMr,
    #[error("invalid QP handle")]
    InvalidQp,
    #[error("PD in use")]
    PdInUse,
    #[error("no available QP")]
    NoAvailableQp,
}
