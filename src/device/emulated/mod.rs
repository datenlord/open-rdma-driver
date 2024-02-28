#![allow(unused)]

use super::{
    DeviceAdaptor, Overflowed, ToCardCtrlRbDesc, ToCardRb, ToCardWorkRbDesc, ToHostCtrlRbDesc,
    ToHostRb, ToHostWorkRbDesc, ToHostWorkRbDescBth,
};

use std::{error::Error, sync::Arc};

mod emulator_rpc_client;
mod hw_consts;
mod ringbuf;

use emulator_rpc_client::RpcClient;
use ringbuf::{Ringbuf, RingbufPointer, RINGBUF_DEPTH, RINGBUF_ELEMENT_SIZE, RINGBUF_PAGE_SIZE};

/// An emulated device implementation of the device.
pub(crate) struct EmulatedDevice {
    to_card_ctrl_rb: ToCardCtrlRb,
    to_host_ctrl_rb: ToHostCtrlRb,
    to_card_work_rb: ToCardWorkRb,
    to_host_work_rb: ToHostWorkRb,
    heap_mem_start_addr: usize,
    rpc_client: Arc<RpcClient>,
}

struct ToCardCtrlRb {
    rb: Ringbuf<RINGBUF_DEPTH, RINGBUF_ELEMENT_SIZE>,
    rpc_client: Arc<RpcClient>,
}

struct ToHostCtrlRb {}

struct ToCardWorkRb {}

struct ToHostWorkRb {}

impl EmulatedDevice {
    /// Initializing an emulated device.
    /// This function needs to be synchronized.
    pub(crate) fn init(
        server_port: u16,
        heap_mem_start_addr: usize,
    ) -> Result<Self, Box<dyn Error>> {
        let rpc_client = Arc::new(RpcClient::new(server_port, heap_mem_start_addr)?);

        #[allow(clippy::arc_with_non_send_sync)]
        Ok(Self {
            to_card_ctrl_rb: ToCardCtrlRb {
                rb: Ringbuf::new(),
                rpc_client: rpc_client.clone(),
            },
            to_host_ctrl_rb: ToHostCtrlRb {},
            to_card_work_rb: ToCardWorkRb {},
            to_host_work_rb: ToHostWorkRb {},
            heap_mem_start_addr,
            rpc_client,
        })
    }

    fn get_pa_by_va(&self, va: usize) -> usize {
        va - self.heap_mem_start_addr
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

    fn read_csr(&self, addr: usize) -> u32 {
        self.rpc_client.read_csr(addr)
    }

    fn write_csr(&self, addr: usize, data: u32) {
        self.rpc_client.write_csr(addr, data);
    }
}

impl ToCardRb<ToCardCtrlRbDesc> for ToCardCtrlRb {
    fn push(&self, _desc: ToCardCtrlRbDesc) -> Result<(), Overflowed> {
        self.rpc_client.write_csr(
            hw_consts::CSR_ADDR_CMD_REQ_QUEUE_HEAD,
            self.rb.get_head().get_index_with_guard() as u32,
        );
        Ok(())
    }
}

impl ToHostRb<ToHostCtrlRbDesc> for ToHostCtrlRb {
    fn pop(&self) -> ToHostCtrlRbDesc {
        unsafe {
            let mut a: Vec<ToHostCtrlRbDesc> = Vec::new();
            a.reserve(1);
            let p: *const ToHostCtrlRbDesc = a.as_ptr();
            std::mem::transmute_copy(&*p)
        }
        // todo!()
    }
}

impl ToHostRb<ToHostWorkRbDesc> for ToHostWorkRb {
    fn pop(&self) -> ToHostWorkRbDesc {
        unsafe {
            let mut a: Vec<ToHostWorkRbDesc> = Vec::new();
            a.reserve(1);
            let p = a.as_ptr();
            std::mem::transmute_copy(&*p)
        }
        // todo!()
    }
}

impl ToCardRb<ToCardWorkRbDesc> for ToCardWorkRb {
    fn push(&self, _desc: ToCardWorkRbDesc) -> Result<(), Overflowed> {
        Ok(())
        // todo!()
    }
}

unsafe impl Send for EmulatedDevice {}
unsafe impl Sync for EmulatedDevice {}
