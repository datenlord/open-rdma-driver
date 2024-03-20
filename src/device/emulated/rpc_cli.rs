use serde::{Deserialize, Serialize};
use std::{
    io::Error as IoError,
    net::{SocketAddr, UdpSocket},
    sync::Arc,
};

use crate::device::{
    constants::{
        CSR_ADDR_CMD_REQ_QUEUE_HEAD, CSR_ADDR_CMD_REQ_QUEUE_TAIL, CSR_ADDR_CMD_RESP_QUEUE_HEAD,
        CSR_ADDR_CMD_RESP_QUEUE_TAIL, CSR_ADDR_META_REPORT_QUEUE_HEAD,
        CSR_ADDR_META_REPORT_QUEUE_TAIL, CSR_ADDR_SEND_QUEUE_HEAD, CSR_ADDR_SEND_QUEUE_TAIL,
    },
    ringbuf::{CsrReaderProxy, CsrWriterProxy},
};

#[derive(Clone)]
pub(super) struct RpcClient(Arc<UdpSocket>);

#[derive(Serialize, Deserialize)]
struct CsrAccessRpcMessage {
    is_write: bool,
    addr: usize,
    value: u32,
}

impl RpcClient {
    pub(super) fn new(server_addr: SocketAddr) -> Result<Self, IoError> {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.connect(server_addr)?;
        Ok(Self(socket.into()))
    }

    pub(super) fn read_csr(&self, addr: usize) -> u32 {
        let msg = CsrAccessRpcMessage {
            is_write: false,
            addr,
            value: 0,
        };

        let send_buf = serde_json::to_vec(&msg).unwrap();
        self.0.send(&send_buf).unwrap();

        let mut recv_buf = [0; 128];
        let recv_cnt = self.0.recv(&mut recv_buf).unwrap();
        let response =
            serde_json::from_slice::<CsrAccessRpcMessage>(&recv_buf[..recv_cnt]).unwrap();

        response.value
    }

    pub(super) fn write_csr(&self, addr: usize, data: u32) {
        let msg = CsrAccessRpcMessage {
            is_write: true,
            addr,
            value: data,
        };

        let send_buf = serde_json::to_vec(&msg).unwrap();
        self.0.send(&send_buf).unwrap();
    }
}

pub(crate) struct ToCardCtrlRbCsrProxy(RpcClient);
impl ToCardCtrlRbCsrProxy {
    const HEAD_CSR: usize = CSR_ADDR_CMD_REQ_QUEUE_HEAD;
    const TAIL_CSR: usize = CSR_ADDR_CMD_REQ_QUEUE_TAIL;
    pub fn new(client: RpcClient) -> Self {
        Self(client)
    }
}
impl CsrWriterProxy for ToCardCtrlRbCsrProxy {
    fn write_head(&self, data: u32) {
        self.0.write_csr(Self::HEAD_CSR, data);
    }
    fn read_tail(&self) -> u32 {
        self.0.read_csr(Self::TAIL_CSR)
    }
}

pub(crate) struct ToHostCtrlRbCsrProxy(RpcClient);

impl ToHostCtrlRbCsrProxy {
    const HEAD_CSR: usize = CSR_ADDR_CMD_RESP_QUEUE_HEAD;
    const TAIL_CSR: usize = CSR_ADDR_CMD_RESP_QUEUE_TAIL;
    pub fn new(client: RpcClient) -> Self {
        Self(client)
    }
}

impl CsrReaderProxy for ToHostCtrlRbCsrProxy {
    fn write_tail(&self, data: u32) {
        self.0.write_csr(Self::TAIL_CSR, data);
    }
    fn read_head(&self) -> u32 {
        self.0.read_csr(Self::HEAD_CSR)
    }
}

pub(crate) struct ToCardWorkRbCsrProxy(RpcClient);

impl ToCardWorkRbCsrProxy {
    const HEAD_CSR: usize = CSR_ADDR_SEND_QUEUE_HEAD;
    const TAIL_CSR: usize = CSR_ADDR_SEND_QUEUE_TAIL;
    pub fn new(client: RpcClient) -> Self {
        Self(client)
    }
}

impl CsrWriterProxy for ToCardWorkRbCsrProxy {
    fn write_head(&self, data: u32) {
        self.0.write_csr(Self::HEAD_CSR, data);
    }
    fn read_tail(&self) -> u32 {
        self.0.read_csr(Self::TAIL_CSR)
    }
}

pub(crate) struct ToHostWorkRbCsrProxy(RpcClient);

impl ToHostWorkRbCsrProxy {
    const HEAD_CSR: usize = CSR_ADDR_META_REPORT_QUEUE_HEAD;
    const TAIL_CSR: usize = CSR_ADDR_META_REPORT_QUEUE_TAIL;
    pub fn new(client: RpcClient) -> Self {
        Self(client)
    }
}

impl CsrReaderProxy for ToHostWorkRbCsrProxy {
    fn write_tail(&self, data: u32) {
        self.0.write_csr(Self::TAIL_CSR, data);
    }
    fn read_head(&self) -> u32 {
        self.0.read_csr(Self::HEAD_CSR)
    }
}
