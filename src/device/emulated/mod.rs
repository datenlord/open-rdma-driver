#![allow(unused)]

use super::{
    constants, ringbuf::Ringbuf, DeviceAdaptor, Overflowed, ToCardCtrlRbDesc, ToCardRb,
    ToCardWorkRbDesc, ToHostCtrlRbDesc, ToHostRb, ToHostWorkRbDesc,
};
use emulator_rpc_client::RpcClient;
use std::{error::Error, net::SocketAddr, sync::Arc, thread, time::Duration};

mod emulator_rpc_client;

/// An emulated device implementation of the device.
pub(crate) struct EmulatedDevice {
    to_card_ctrl_rb: ToCardCtrlRb,
    to_host_ctrl_rb: ToHostCtrlRb,
    to_card_work_rb: ToCardWorkRb,
    to_host_work_rb: ToHostWorkRb,
    heap_mem_start_addr: usize,
    rpc_client: Arc<RpcClient>, // TODO: remove Arc
}

struct ToCardCtrlRb {
    rb: Ringbuf<
        { constants::RINGBUF_DEPTH },
        { constants::RINGBUF_ELEM_SIZE },
        { constants::RINGBUF_PAGE_SIZE },
    >,
    rpc_client: Arc<RpcClient>,
}

struct ToHostCtrlRb {
    rb: Ringbuf<
        { constants::RINGBUF_DEPTH },
        { constants::RINGBUF_ELEM_SIZE },
        { constants::RINGBUF_PAGE_SIZE },
    >,
    rpc_client: Arc<RpcClient>,
}

struct ToCardWorkRb {
    rb: Ringbuf<
        { constants::RINGBUF_DEPTH },
        { constants::RINGBUF_ELEM_SIZE },
        { constants::RINGBUF_PAGE_SIZE },
    >,
    rpc_client: Arc<RpcClient>,
}

struct ToHostWorkRb {
    rb: Ringbuf<
        { constants::RINGBUF_DEPTH },
        { constants::RINGBUF_ELEM_SIZE },
        { constants::RINGBUF_PAGE_SIZE },
    >,
    rpc_client: Arc<RpcClient>,
}

impl EmulatedDevice {
    /// Initializing an emulated device.
    /// This function needs to be synchronized.
    pub(crate) fn init(
        rpc_server_addr: SocketAddr,
        heap_mem_start_addr: usize,
    ) -> Result<Self, Box<dyn Error>> {
        let rpc_client = Arc::new(RpcClient::new(rpc_server_addr, heap_mem_start_addr)?);

        #[allow(clippy::arc_with_non_send_sync)]
        Ok(Self {
            to_card_ctrl_rb: ToCardCtrlRb {
                rb: Ringbuf::new(),
                rpc_client: rpc_client.clone(),
            },
            to_host_ctrl_rb: ToHostCtrlRb {
                rb: Ringbuf::new(),
                rpc_client: rpc_client.clone(),
            },
            to_card_work_rb: ToCardWorkRb {
                rb: Ringbuf::new(),
                rpc_client: rpc_client.clone(),
            },
            to_host_work_rb: ToHostWorkRb {
                rb: Ringbuf::new(),
                rpc_client: rpc_client.clone(),
            },
            heap_mem_start_addr,
            rpc_client,
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

    fn read_csr(&self, addr: usize) -> u32 {
        self.rpc_client.read_csr(addr)
    }

    fn write_csr(&self, addr: usize, data: u32) {
        self.rpc_client.write_csr(addr, data);
    }

    fn get_phys_addr(&self, virt_addr: usize) -> usize {
        virt_addr - self.heap_mem_start_addr
    }
}

impl ToCardRb<ToCardCtrlRbDesc> for ToCardCtrlRb {
    fn push(&self, desc: ToCardCtrlRbDesc) -> Result<(), Overflowed> {
        let desc_cnt = desc.serialized_desc_cnt();

        let Some(mut writer) = self.rb.write(desc_cnt) else {
            return Err(Overflowed);
        };

        let mem = writer.next().unwrap();
        desc.write(mem);
        drop(writer); // writer should be dropped to update the head pointer

        self.rpc_client.write_csr(
            constants::CSR_ADDR_CMD_REQ_QUEUE_HEAD,
            self.rb.head() as u32,
        );

        Ok(())
    }
}

impl ToHostRb<ToHostCtrlRbDesc> for ToHostCtrlRb {
    fn pop(&self) -> ToHostCtrlRbDesc {
        loop {
            let mut reader = self.rb.read();

            let Some(mem) = reader.next() else {
                drop(reader); // reader should be dropped to update the tail pointer
                thread::sleep(Duration::from_millis(1)); // sleep for a while
                continue;
            };

            let desc = ToHostCtrlRbDesc::read(mem);
            drop(reader); // reader should be dropped to update the tail pointer

            self.rpc_client.write_csr(
                constants::CSR_ADDR_CMD_RESP_QUEUE_TAIL,
                self.rb.tail() as u32,
            );

            return desc;
        }
    }
}

impl ToCardRb<ToCardWorkRbDesc> for ToCardWorkRb {
    fn push(&self, desc: ToCardWorkRbDesc) -> Result<(), Overflowed> {
        let desc_cnt = desc.serialized_desc_cnt();

        let Some(mut writer) = self.rb.write(desc_cnt) else {
            return Err(Overflowed);
        };

        desc.write_0(writer.next().unwrap());
        desc.write_1(writer.next().unwrap());
        desc.write_2(writer.next().unwrap());

        if desc_cnt == 4 {
            desc.write_3(writer.next().unwrap());
        }

        drop(writer); // writer should be dropped to update the head pointer

        self.rpc_client
            .write_csr(constants::CSR_ADDR_SEND_QUEUE_HEAD, self.rb.head() as u32);

        Ok(())
    }
}

impl ToHostRb<ToHostWorkRbDesc> for ToHostWorkRb {
    fn pop(&self) -> ToHostWorkRbDesc {
        loop {
            let mut reader = self.rb.read();

            let Some(mem) = reader.next() else {
                drop(reader); // reader should be dropped to update the tail pointer
                thread::sleep(Duration::from_millis(1)); // sleep for a while
                continue;
            };

            let mut read_res = ToHostWorkRbDesc::read(mem);

            let desc = loop {
                match read_res {
                    Ok(desc) => break desc,
                    Err(desc) => read_res = desc.read(mem),
                }
            };

            drop(reader); // reader should be dropped to update the tail pointer

            self.rpc_client.write_csr(
                constants::CSR_ADDR_META_REPORT_QUEUE_TAIL,
                self.rb.tail() as u32,
            );

            return desc;
        }
    }
}

unsafe impl Send for EmulatedDevice {}
unsafe impl Sync for EmulatedDevice {}
