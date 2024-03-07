use std::{
    error::Error,
    sync::Arc,
    thread::{spawn, JoinHandle},
};

use crossbeam_queue::SegQueue;

use self::{
    logic::BlueRDMALogic,
    net_agent::udp_agent::{UDPReceiveAgent, UDPSendAgent},
};

use super::{
    scheduler::{round_robin::RoundRobinStrategy, DescriptorScheduler},
    DeviceAdaptor, Overflowed, ToCardCtrlRbDesc, ToCardRb, ToCardWorkRbDesc, ToHostCtrlRbDesc,
    ToHostRb, ToHostWorkRbDesc,
};

mod logic;
mod net_agent;
mod packet;
mod packet_processor;
#[cfg(test)]
mod tests;
mod types;
mod utils;

/// An software device implementation of the device.
/// 
/// # Examples:
/// ```
/// let device = SoftwareDevice::init().unwrap();
/// let ctrl_rb = device.to_card_ctrl_rb();
// // ctrl_rb.push(desc) // create mr or qp
/// let data_send_rb = device.to_card_work_rb();
/// // data_rb.push(desc) // send data
/// let data_recv_rb = device.to_host_work_rb();
/// // data_recv_rb.pop() // recv data
/// ```
#[allow(dead_code)]
pub(crate) struct SoftwareDevice {
    recv_agent: UDPReceiveAgent,
    polling_thread: JoinHandle<()>,
    to_card_ctrl_rb: ToCardCtrlRb,
    to_host_ctrl_rb: ToHostCtrlRb,
    to_card_work_rb: ToCardWorkRb,
    to_host_work_rb: ToHostWorkRb,
}

struct ToCardCtrlRb(Arc<BlueRDMALogic>);
struct ToHostCtrlRb;
struct ToCardWorkRb(Arc<DescriptorScheduler>);
struct ToHostWorkRb(Arc<SegQueue<ToHostWorkRbDesc>>);

impl SoftwareDevice {
    /// Initializing an software device.
    pub(crate) fn init() -> Result<Self, Box<dyn Error>> {
        let send_agent = UDPSendAgent::new()?;
        let device = Arc::new(BlueRDMALogic::new(Arc::new(send_agent)));
        // The strategy is a global singleton, so we leak it
        let round_robin = Arc::new(RoundRobinStrategy::new());
        let scheduler = DescriptorScheduler::new(round_robin);
        let scheduler = Arc::new(scheduler);
        let to_host_queue = device.get_to_host_descriptor_queue();
        let mut recv_agent = UDPReceiveAgent::new(device.clone())?;
        recv_agent.start()?;

        let this_scheduler = scheduler.clone();
        let this_device = device.clone();
        let polling_thread = spawn(move || loop {
            if let Some(to_card_ctrl_rb_desc) = this_scheduler.pop() {
                let _ = this_device.send(to_card_ctrl_rb_desc);
            }
        });
        let to_card_work_rb = ToCardWorkRb(scheduler);
        Ok(Self {
            recv_agent,
            polling_thread,
            to_card_ctrl_rb: ToCardCtrlRb(device),
            to_host_ctrl_rb: ToHostCtrlRb,
            to_card_work_rb,
            to_host_work_rb: ToHostWorkRb(to_host_queue),
        })
    }
}

impl DeviceAdaptor for SoftwareDevice {
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
    fn push(&self, desc: ToCardCtrlRbDesc) -> Result<(), Overflowed> {
        self.0.update(desc).unwrap();
        Ok(())
    }
}

impl ToHostRb<ToHostCtrlRbDesc> for ToHostCtrlRb {
    fn pop(&self) -> Option<ToHostCtrlRbDesc> {
        todo!()
    }
}

impl ToHostRb<ToHostWorkRbDesc> for ToHostWorkRb {
    fn pop(&self) -> Option<ToHostWorkRbDesc> {
        self.0.pop()
    }
}

impl ToCardRb<ToCardWorkRbDesc> for ToCardWorkRb {
    fn push(&self, desc: ToCardWorkRbDesc) -> Result<(), Overflowed> {
        self.0.push(desc);
        Ok(())
    }
}