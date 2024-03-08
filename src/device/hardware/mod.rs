use super::{
    DeviceAdaptor, Overflowed, ToCardCtrlRbDesc, ToCardRb, ToCardWorkRbDesc, ToHostCtrlRbDesc,
    ToHostRb, ToHostWorkRbDesc,
};
use std::error::Error;

pub(crate) struct HardwareDevice {
    to_card_ctrl_rb: ToCardCtrlRb,
    to_host_ctrl_rb: ToHostCtrlRb,
    to_card_work_rb: ToCardWorkRb,
    to_host_work_rb: ToHostWorkRb,
}

struct ToCardCtrlRb;
struct ToHostCtrlRb;
struct ToCardWorkRb;
struct ToHostWorkRb;

impl HardwareDevice {
    pub(crate) fn init() -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            to_card_ctrl_rb: ToCardCtrlRb,
            to_host_ctrl_rb: ToHostCtrlRb,
            to_card_work_rb: ToCardWorkRb,
            to_host_work_rb: ToHostWorkRb,
        })
    }
}

impl DeviceAdaptor for HardwareDevice {
    fn to_card_ctrl_rb(&self) -> &dyn ToCardRb<ToCardCtrlRbDesc> {
        &self.to_card_ctrl_rb
    }

    fn to_host_ctrl_rb(&self) -> &dyn ToHostRb<ToHostCtrlRbDesc> {
        &self.to_host_ctrl_rb
    }

    fn to_card_work_rb(&self) -> &dyn ToCardRb<ToCardWorkRbDesc> {
        &self.to_card_work_rb
    }

    fn to_host_work_rb(&self) -> &dyn ToHostRb<ToHostWorkRbDesc> {
        &self.to_host_work_rb
    }

    fn read_csr(&self, _addr: usize) -> u32 {
        todo!()
    }

    fn write_csr(&self, _addr: usize, _data: u32) {
        todo!()
    }

    fn get_phys_addr(&self, virt_addr: usize) -> usize {
        virt_addr
    }
}

impl ToCardRb<ToCardCtrlRbDesc> for ToCardCtrlRb {
    fn push(&self, _desc: ToCardCtrlRbDesc) -> Result<(), Overflowed> {
        todo!()
    }
}

impl ToHostRb<ToHostCtrlRbDesc> for ToHostCtrlRb {
    fn pop(&self) -> ToHostCtrlRbDesc {
        todo!()
    }
}

impl ToHostRb<ToHostWorkRbDesc> for ToHostWorkRb {
    fn pop(&self) -> ToHostWorkRbDesc {
        todo!()
    }
}

impl ToCardRb<ToCardWorkRbDesc> for ToCardWorkRb {
    fn push(&self, _desc: ToCardWorkRbDesc) -> Result<(), Overflowed> {
        todo!()
    }
}
