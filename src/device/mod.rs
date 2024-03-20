use std::sync::Arc;

use thiserror::Error;

mod constants;
mod emulated;
mod hardware;
mod ringbuf;
mod software;
mod types;

pub mod scheduler;
pub use types::ToCardWorkRbDesc;

pub(crate) use self::{
    emulated::EmulatedDevice, hardware::HardwareDevice, software::SoftwareDevice, types::*,
};

/// Public interface for a device. Can be a real hardware device or a software emulation.
pub(crate) trait DeviceAdaptor: Send + Sync {
    fn to_card_ctrl_rb(&self) -> Arc<dyn ToCardRb<ToCardCtrlRbDesc>>;
    fn to_host_ctrl_rb(&self) -> Arc<dyn ToHostRb<ToHostCtrlRbDesc>>;

    fn to_card_work_rb(&self) -> Arc<dyn ToCardRb<ToCardWorkRbDesc>>;
    fn to_host_work_rb(&self) -> Arc<dyn ToHostRb<ToHostWorkRbDesc>>;

    fn read_csr(&self, addr: usize) -> u32;
    fn write_csr(&self, addr: usize, data: u32);

    fn get_phys_addr(&self, virt_addr: usize) -> usize;
}

/// Generic interface for a to-card ring buffer.
pub(crate) trait ToCardRb<D> {
    fn push(&self, desc: D) -> Result<(), Overflowed>;
}

/// Generic interface for a to-host ring buffer.
pub(crate) trait ToHostRb<D> {
    fn pop(&self) -> D;
}

/// An error indicating that a ring buffer overflowed.
#[derive(Debug, Error)]
#[error("ring buffer overflowed")]
pub(crate) struct Overflowed;

#[derive(Debug, Error)]
#[error("net socket failed to bind the port")]
pub(crate) struct PortBindFailed;
