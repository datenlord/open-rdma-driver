use serde::{Deserialize, Serialize};
use std::{
    io::Error as IoError,
    net::{SocketAddr, UdpSocket},
};

pub(super) struct RpcClient(UdpSocket);

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
        Ok(Self(socket))
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
