#![allow(unused)]

use super::{
    DeviceAdaptor, Overflowed, ToCardCtrlRbDesc, ToCardRb, ToCardWorkRbDesc, ToHostCtrlRbDesc,
    ToHostRb, ToHostWorkRbDesc,
};
use shared_memory::{Shmem, ShmemConf};
use std::{error::Error, sync::Arc};

const SHM_PATH: &str = "/PATH/TO/SHM";

/// An emulated device implementation of the device.
pub(crate) struct EmulatedDevice {
    to_card_ctrl_rb: ToCardCtrlRb,
    to_host_ctrl_rb: ToHostCtrlRb,
    to_card_work_rb: ToCardWorkRb,
    to_host_work_rb: ToHostWorkRb,
    shm: Arc<Shmem>,
}

struct ToCardCtrlRb {
    shm: Arc<Shmem>,
}

struct ToHostCtrlRb {
    shm: Arc<Shmem>,
}

struct ToCardWorkRb {
    shm: Arc<Shmem>,
}

struct ToHostWorkRb {
    shm: Arc<Shmem>,
}

impl EmulatedDevice {
    /// Initializing an emulated device.
    /// This function needs to be synchronized.
    pub(crate) fn init() -> Result<Self, Box<dyn Error>> {
        #[allow(clippy::arc_with_non_send_sync)]
        let shm = Arc::new(ShmemConf::new().flink(SHM_PATH).open()?);

        Ok(Self {
            to_card_ctrl_rb: ToCardCtrlRb { shm: shm.clone() },
            to_host_ctrl_rb: ToHostCtrlRb { shm: shm.clone() },
            to_card_work_rb: ToCardWorkRb { shm: shm.clone() },
            to_host_work_rb: ToHostWorkRb { shm: shm.clone() },
            shm,
        })
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

unsafe impl Send for EmulatedDevice {}
unsafe impl Sync for EmulatedDevice {}
