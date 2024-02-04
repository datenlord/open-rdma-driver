use crate::device::{DeviceAdaptor, EmulatedDevice, HardwareDevice};
use std::{sync::Arc, thread};

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
    pub fn new_emulated() -> Self {
        let inner = Arc::new(DeviceInner {
            is_emulated: true,
            adaptor: EmulatedDevice::init(),
        });

        let dev = Self(inner);

        let dev_for_poll_ctrl_rb = dev.clone();
        let dev_for_poll_work_rb = dev.clone();

        thread::spawn(move || dev_for_poll_ctrl_rb.poll_ctrl_rb());
        thread::spawn(move || dev_for_poll_work_rb.poll_work_rb());

        dev
    }

    pub fn new_hardware() -> Self {
        let inner = Arc::new(DeviceInner {
            is_emulated: false,
            adaptor: HardwareDevice::init(),
        });

        let dev = Self(inner);

        let dev_for_poll_ctrl_rb = dev.clone();
        let dev_for_poll_work_rb = dev.clone();

        thread::spawn(move || dev_for_poll_ctrl_rb.poll_ctrl_rb());
        thread::spawn(move || dev_for_poll_work_rb.poll_work_rb());

        dev
    }
}
