use super::{
    DeviceAdaptor, Overflowed, ToCardCtrlRbDesc, ToCardRb, ToCardWorkRbDesc, ToHostCtrlRbDesc,
    ToHostRb, ToHostWorkRbDesc,
};

/// An emulated device implementation of the device.
pub(crate) struct EmulatedDevice {
    to_card_ctrl_rb: ToCardCtrlRb,
    to_host_ctrl_rb: ToHostCtrlRb,
    to_card_work_rb: ToCardWorkRb,
    to_host_work_rb: ToHostWorkRb,
}

struct ToCardCtrlRb;
struct ToHostCtrlRb;
struct ToCardWorkRb;
struct ToHostWorkRb;

impl EmulatedDevice {
    /// Initializing an emulated device.
    /// This function needs to be synchronized.
    /// TODO: is this fallible?
    pub(crate) fn init() -> Self {
        Self {
            to_card_ctrl_rb: ToCardCtrlRb,
            to_host_ctrl_rb: ToHostCtrlRb,
            to_card_work_rb: ToCardWorkRb,
            to_host_work_rb: ToHostWorkRb,
        }
    }
}

impl DeviceAdaptor for EmulatedDevice {
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
