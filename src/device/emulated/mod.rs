use self::rpc_cli::RpcClient;
use super::{
    constants, ringbuf::Ringbuf, DeviceAdaptor, Overflowed, ToCardCtrlRbDesc, ToCardRb,
    ToCardWorkRbDesc, ToHostCtrlRbDesc, ToHostRb, ToHostWorkRbDesc,
};
use std::{error::Error, net::SocketAddr, thread, time::Duration};

mod rpc_cli;

/// An emulated device implementation of the device.
pub(crate) struct EmulatedDevice {
    to_card_ctrl_rb: Ringbuf<
        { constants::RINGBUF_DEPTH },
        { constants::RINGBUF_ELEM_SIZE },
        { constants::RINGBUF_PAGE_SIZE },
    >,
    to_host_ctrl_rb: Ringbuf<
        { constants::RINGBUF_DEPTH },
        { constants::RINGBUF_ELEM_SIZE },
        { constants::RINGBUF_PAGE_SIZE },
    >,
    to_card_work_rb: Ringbuf<
        { constants::RINGBUF_DEPTH },
        { constants::RINGBUF_ELEM_SIZE },
        { constants::RINGBUF_PAGE_SIZE },
    >,
    to_host_work_rb: Ringbuf<
        { constants::RINGBUF_DEPTH },
        { constants::RINGBUF_ELEM_SIZE },
        { constants::RINGBUF_PAGE_SIZE },
    >,
    heap_mem_start_addr: usize,
    rpc_cli: RpcClient,
}

impl EmulatedDevice {
    /// Initializing an emulated device.
    /// This function needs to be synchronized.
    pub(crate) fn init(
        rpc_server_addr: SocketAddr,
        heap_mem_start_addr: usize,
    ) -> Result<Self, Box<dyn Error>> {
        let rpc_cli = RpcClient::new(rpc_server_addr)?;
        let to_card_ctrl_rb = Ringbuf::new();
        let to_host_ctrl_rb = Ringbuf::new();
        let to_card_work_rb = Ringbuf::new();
        let to_host_work_rb = Ringbuf::new();

        // TODO: refactor this, should call function to get PA instead of calc it directly.
        let pa_of_ringbuf = to_card_ctrl_rb.get_ringbuf_addr() - heap_mem_start_addr;
        rpc_cli.write_csr(
            constants::CSR_ADDR_CMD_REQ_QUEUE_ADDR_LOW,
            (pa_of_ringbuf & 0xFFFFFFFF) as u32,
        );
        rpc_cli.write_csr(
            constants::CSR_ADDR_CMD_REQ_QUEUE_ADDR_HIGH,
            (pa_of_ringbuf >> 32) as u32,
        );

        let pa_of_ringbuf = to_host_ctrl_rb.get_ringbuf_addr() - heap_mem_start_addr;
        rpc_cli.write_csr(
            constants::CSR_ADDR_CMD_RESP_QUEUE_ADDR_LOW,
            (pa_of_ringbuf & 0xFFFFFFFF) as u32,
        );
        rpc_cli.write_csr(
            constants::CSR_ADDR_CMD_RESP_QUEUE_ADDR_HIGH,
            (pa_of_ringbuf >> 32) as u32,
        );

        let pa_of_ringbuf = to_card_work_rb.get_ringbuf_addr() - heap_mem_start_addr;
        rpc_cli.write_csr(
            constants::CSR_ADDR_SEND_QUEUE_ADDR_LOW,
            (pa_of_ringbuf & 0xFFFFFFFF) as u32,
        );
        rpc_cli.write_csr(
            constants::CSR_ADDR_SEND_QUEUE_ADDR_HIGH,
            (pa_of_ringbuf >> 32) as u32,
        );

        let pa_of_ringbuf = to_host_work_rb.get_ringbuf_addr() - heap_mem_start_addr;
        rpc_cli.write_csr(
            constants::CSR_ADDR_META_REPORT_QUEUE_ADDR_LOW,
            (pa_of_ringbuf & 0xFFFFFFFF) as u32,
        );
        rpc_cli.write_csr(
            constants::CSR_ADDR_META_REPORT_QUEUE_ADDR_HIGH,
            (pa_of_ringbuf >> 32) as u32,
        );

        Ok(Self {
            to_card_ctrl_rb,
            to_host_ctrl_rb,
            to_card_work_rb,
            to_host_work_rb,
            heap_mem_start_addr,
            rpc_cli,
        })
    }
}

impl DeviceAdaptor for EmulatedDevice {
    fn to_card_ctrl_rb(&self) -> &dyn ToCardRb<ToCardCtrlRbDesc> {
        self
    }

    fn to_host_ctrl_rb(&self) -> &dyn ToHostRb<ToHostCtrlRbDesc> {
        self
    }

    fn to_card_work_rb(&self) -> &dyn ToCardRb<ToCardWorkRbDesc> {
        self
    }

    fn to_host_work_rb(&self) -> &dyn ToHostRb<ToHostWorkRbDesc> {
        self
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
        let desc_cnt = desc.serialized_desc_cnt();

        let Some(mut writer) = self.to_card_ctrl_rb.write(desc_cnt) else {
            return Err(Overflowed);
        };

        let mem = writer.next().unwrap();
        desc.write(mem);
        drop(writer); // writer should be dropped to update the head pointer

        self.rpc_cli.write_csr(
            constants::CSR_ADDR_CMD_REQ_QUEUE_HEAD,
            self.to_card_ctrl_rb.head() as u32,
        );

        Ok(())
    }
}

impl ToHostRb<ToHostCtrlRbDesc> for EmulatedDevice {
    fn pop(&self) -> ToHostCtrlRbDesc {
        loop {
            let new_head = self
                .rpc_cli
                .read_csr(constants::CSR_ADDR_CMD_RESP_QUEUE_HEAD);
            self.to_host_ctrl_rb.set_head(new_head as usize);
            let mut reader = self.to_host_ctrl_rb.read();
            let Some(mem) = reader.next() else {
                drop(reader); // reader should be dropped to update the tail pointer
                thread::sleep(Duration::from_millis(1)); // sleep for a while
                continue;
            };

            let desc = ToHostCtrlRbDesc::read(mem);
            drop(reader); // reader should be dropped to update the tail pointer

            self.rpc_cli.write_csr(
                constants::CSR_ADDR_CMD_RESP_QUEUE_TAIL,
                self.to_host_ctrl_rb.tail() as u32,
            );

            return desc;
        }
    }
}

impl ToCardRb<ToCardWorkRbDesc> for EmulatedDevice {
    fn push(&self, desc: ToCardWorkRbDesc) -> Result<(), Overflowed> {
        let desc_cnt = desc.serialized_desc_cnt();

        let Some(mut writer) = self.to_card_work_rb.write(desc_cnt) else {
            return Err(Overflowed);
        };

        desc.write_0(writer.next().unwrap());
        desc.write_1(writer.next().unwrap());
        desc.write_2(writer.next().unwrap());

        if desc_cnt == 4 {
            desc.write_3(writer.next().unwrap());
        }

        drop(writer); // writer should be dropped to update the head pointer

        self.rpc_cli.write_csr(
            constants::CSR_ADDR_SEND_QUEUE_HEAD,
            self.to_card_work_rb.head() as u32,
        );

        Ok(())
    }
}

impl ToHostRb<ToHostWorkRbDesc> for EmulatedDevice {
    fn pop(&self) -> ToHostWorkRbDesc {
        loop {
            let new_head = self
                .rpc_cli
                .read_csr(constants::CSR_ADDR_META_REPORT_QUEUE_HEAD);
            self.to_host_work_rb.set_head(new_head as usize);
            let mut reader = self.to_host_work_rb.read();

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

            self.rpc_cli.write_csr(
                constants::CSR_ADDR_META_REPORT_QUEUE_TAIL,
                self.to_host_work_rb.tail() as u32,
            );

            return desc;
        }
    }
}
