use crate::device::{DeviceAdaptor, EmulatedDevice, HardwareDevice};
use std::{error::Error as StdError, sync::Arc, thread};
use thiserror::Error;

mod device;
mod poll;

#[derive(Clone)]
pub struct Device(Arc<DeviceInner<dyn DeviceAdaptor>>);

#[allow(unused)]
struct DeviceInner<D: ?Sized> {
    is_emulated: bool,
    adaptor: D,
}

impl Device {
    pub fn new_emulated() -> Result<Self, Error> {
        let inner = Arc::new(DeviceInner {
            is_emulated: true,
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
            adaptor: HardwareDevice::init().map_err(Error::Device)?,
        });

        let dev = Self(inner);

        let dev_for_poll_ctrl_rb = dev.clone();
        let dev_for_poll_work_rb = dev.clone();

        thread::spawn(move || dev_for_poll_ctrl_rb.poll_ctrl_rb());
        thread::spawn(move || dev_for_poll_work_rb.poll_work_rb());

        Ok(dev)
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Device(Box<dyn StdError>),
}
