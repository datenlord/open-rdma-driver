use self::rpc_cli::{
    RpcClient, ToCardCtrlRbCsrProxy, ToCardWorkRbCsrProxy, ToHostCtrlRbCsrProxy,
    ToHostWorkRbCsrProxy,
};
use super::{
    constants, ringbuf::Ringbuf, DeviceAdaptor, Overflowed, ToCardCtrlRbDesc, ToCardRb,
    ToCardWorkRbDesc, ToHostCtrlRbDesc, ToHostRb, ToHostWorkRbDesc,
};
use std::{
    error::Error,
    net::SocketAddr, sync::{Arc, Mutex},
};

mod rpc_cli;

type ToCardCtrlRb = Ringbuf<
    ToCardCtrlRbCsrProxy,
    { constants::RINGBUF_DEPTH },
    { constants::RINGBUF_ELEM_SIZE },
    { constants::RINGBUF_PAGE_SIZE },
>;

type ToHostCtrlRb = Ringbuf<
    ToHostCtrlRbCsrProxy,
    { constants::RINGBUF_DEPTH },
    { constants::RINGBUF_ELEM_SIZE },
    { constants::RINGBUF_PAGE_SIZE },
>;

type ToCardWorkRb = Ringbuf<
    ToCardWorkRbCsrProxy,
    { constants::RINGBUF_DEPTH },
    { constants::RINGBUF_ELEM_SIZE },
    { constants::RINGBUF_PAGE_SIZE },
>;

type ToHostWorkRb = Ringbuf<
    ToHostWorkRbCsrProxy,
    { constants::RINGBUF_DEPTH },
    { constants::RINGBUF_ELEM_SIZE },
    { constants::RINGBUF_PAGE_SIZE },
>;

/// An emulated device implementation of the device.
pub(crate) struct EmulatedDevice {
    // FIXME: Temporarily ,we use Mutex to make the Rb imuumtable as well as thread safe
    to_card_ctrl_rb: Mutex<ToCardCtrlRb>,
    to_host_ctrl_rb: Mutex<ToHostCtrlRb>,
    to_card_work_rb: Mutex<ToCardWorkRb>,
    to_host_work_rb: Mutex<ToHostWorkRb>,
    heap_mem_start_addr: usize,
    rpc_cli: RpcClient,
}

impl EmulatedDevice {
    /// Initializing an emulated device.
    /// This function needs to be synchronized.
    pub(crate) fn init(
        rpc_server_addr: SocketAddr,
        heap_mem_start_addr: usize,
    ) -> Result<Arc<Self>, Box<dyn Error>> {
        let rpc_cli = RpcClient::new(rpc_server_addr)?;

        let (to_card_ctrl_rb, to_card_ctrl_rb_addr) =
            ToCardCtrlRb::new(ToCardCtrlRbCsrProxy::new(rpc_cli.clone()));
        let (to_host_ctrl_rb, to_host_ctrl_rb_addr) =
            ToHostCtrlRb::new(ToHostCtrlRbCsrProxy::new(rpc_cli.clone()));
        let (to_card_work_rb, to_card_work_rb_addr) =
            ToCardWorkRb::new(ToCardWorkRbCsrProxy::new(rpc_cli.clone()));
        let (to_host_work_rb, to_host_work_rb_addr) =
            ToHostWorkRb::new(ToHostWorkRbCsrProxy::new(rpc_cli.clone()));

        let dev = Arc::new(Self {
            to_card_ctrl_rb: Mutex::new(to_card_ctrl_rb),
            to_host_ctrl_rb: Mutex::new(to_host_ctrl_rb),
            to_card_work_rb: Mutex::new(to_card_work_rb),
            to_host_work_rb: Mutex::new(to_host_work_rb),
            heap_mem_start_addr,
            rpc_cli,
        });

        let pa_of_ringbuf = dev.get_phys_addr(to_card_ctrl_rb_addr);
        dev.rpc_cli.write_csr(
            constants::CSR_ADDR_CMD_REQ_QUEUE_ADDR_LOW,
            (pa_of_ringbuf & 0xFFFFFFFF) as u32,
        );
        dev.rpc_cli.write_csr(
            constants::CSR_ADDR_CMD_REQ_QUEUE_ADDR_HIGH,
            (pa_of_ringbuf >> 32) as u32,
        );

        let pa_of_ringbuf = dev.get_phys_addr(to_host_ctrl_rb_addr);
        dev.rpc_cli.write_csr(
            constants::CSR_ADDR_CMD_RESP_QUEUE_ADDR_LOW,
            (pa_of_ringbuf & 0xFFFFFFFF) as u32,
        );
        dev.rpc_cli.write_csr(
            constants::CSR_ADDR_CMD_RESP_QUEUE_ADDR_HIGH,
            (pa_of_ringbuf >> 32) as u32,
        );

        let pa_of_ringbuf = dev.get_phys_addr(to_card_work_rb_addr);
        dev.rpc_cli.write_csr(
            constants::CSR_ADDR_SEND_QUEUE_ADDR_LOW,
            (pa_of_ringbuf & 0xFFFFFFFF) as u32,
        );
        dev.rpc_cli.write_csr(
            constants::CSR_ADDR_SEND_QUEUE_ADDR_HIGH,
            (pa_of_ringbuf >> 32) as u32,
        );

        let pa_of_ringbuf = dev.get_phys_addr(to_host_work_rb_addr);
        dev.rpc_cli.write_csr(
            constants::CSR_ADDR_META_REPORT_QUEUE_ADDR_LOW,
            (pa_of_ringbuf & 0xFFFFFFFF) as u32,
        );
        dev.rpc_cli.write_csr(
            constants::CSR_ADDR_META_REPORT_QUEUE_ADDR_HIGH,
            (pa_of_ringbuf >> 32) as u32,
        );

        Ok(dev)
    }
}

impl DeviceAdaptor for Arc<EmulatedDevice> {
    fn to_card_ctrl_rb(&self) -> Arc<dyn ToCardRb<ToCardCtrlRbDesc>> {
        self.clone()
    }

    fn to_host_ctrl_rb(&self) -> Arc<dyn ToHostRb<ToHostCtrlRbDesc>> {
        self.clone()
    }

    fn to_card_work_rb(&self) -> Arc<dyn ToCardRb<ToCardWorkRbDesc>> {
        self.clone()
    }

    fn to_host_work_rb(&self) -> Arc<dyn ToHostRb<ToHostWorkRbDesc>> {
        self.clone()
    }

    fn read_csr(&self, addr: usize) -> u32 {
        self.rpc_cli.read_csr(addr)
    }

    fn write_csr(&self, addr: usize, data: u32) {
        self.rpc_cli.write_csr(addr, data);
    }

    fn get_phys_addr(&self, virt_addr: usize) -> usize {
        virt_addr - self.heap_mem_start_addr
    }
}

impl ToCardRb<ToCardCtrlRbDesc> for EmulatedDevice {
    fn push(&self, desc: ToCardCtrlRbDesc) -> Result<(), Overflowed> {
        let mut guard = self.to_card_ctrl_rb.lock().unwrap();
        let mut writer = guard.write();

        let mem = writer.next().unwrap();
        desc.write(mem);

        Ok(())
    }
}

impl ToHostRb<ToHostCtrlRbDesc> for EmulatedDevice {
    fn pop(&self) -> ToHostCtrlRbDesc {
        let mut guard = self.to_host_ctrl_rb.lock().unwrap();
        let mut reader = guard.read();
        let mem = reader.next().unwrap();
        ToHostCtrlRbDesc::read(mem)
    }
}

impl ToCardRb<ToCardWorkRbDesc> for EmulatedDevice {
    fn push(&self, desc: ToCardWorkRbDesc) -> Result<(), Overflowed> {
        let desc_cnt = desc.serialized_desc_cnt();
        // TODO: the card might not be able to handle "part of the desc"
        // So me might need to ensure we have enough space to write the whole desc before writing
        let mut guard = self.to_card_work_rb.lock().unwrap();
        let mut writer = guard.write();
        desc.write_0(writer.next().unwrap());
        desc.write_1(writer.next().unwrap());
        desc.write_2(writer.next().unwrap());

        if desc_cnt == 4 {
            desc.write_3(writer.next().unwrap());
        }

        Ok(())
    }
}

// TODO: refactor the mechanism to handle ringbuf. It's a kind of complex
impl ToHostRb<ToHostWorkRbDesc> for EmulatedDevice {
    fn pop(&self) -> ToHostWorkRbDesc {
        let mut guard = self.to_host_work_rb.lock().unwrap();
        let mut reader = guard.read();

        let mem = reader.next().unwrap();
        let mut read_res = ToHostWorkRbDesc::read(mem);

        loop {
            match read_res {
                Ok(desc) => break desc,
                Err(desc) => {
                    let mem = reader.next().unwrap();
                    read_res = desc.read(mem);
                    match read_res {
                        Ok(desc) => break desc,
                        Err(_) => {
                            todo!();
                        }
                    }
                }
            }
        }
    }
}
