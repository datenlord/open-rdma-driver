use serde::{Deserialize, Serialize};
use serde_json;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Mutex;
use std::{error::Error, sync::Arc};

pub(crate) struct RpcClient {
    emulator_socket: Mutex<UdpSocket>,
    emulator_address: SocketAddr,
}

#[derive(Serialize, Deserialize)]
struct CsrAccessRpcMessage {
    is_write: bool,
    addr: usize,
    value: u32,
}

impl RpcClient {
    pub(crate) fn new(
        server_port: u16,
        heap_mem_start_addr: usize,
    ) -> Result<Self, Box<dyn Error>> {
        let emulator_socket =
            UdpSocket::bind("0.0.0.0:0").expect("EmulatedDevice can't bind to addr");
        let emulator_address = format!("0.0.0.0:{}", server_port)
            .parse()
            .expect("EmulatedDevice parse server addr error");

        #[allow(clippy::arc_with_non_send_sync)]
        Ok(Self {
            emulator_socket: Mutex::new(emulator_socket),
            emulator_address,
        })
    }

    pub(crate) fn read_csr(&self, addr: usize) -> u32 {
        let msg = CsrAccessRpcMessage {
            is_write: false,
            addr,
            value: 0,
        };
        let send_buf = serde_json::to_vec(&msg).unwrap();
        let emulator_socket = self.emulator_socket.lock().unwrap();
        emulator_socket.send_to(&send_buf, self.emulator_address);
        let mut recv_buf = Vec::new();
        recv_buf.resize(128, 0);
        let recv_cnt = emulator_socket.recv(&mut recv_buf).unwrap();
        let response: CsrAccessRpcMessage = serde_json::from_slice(&recv_buf[..recv_cnt]).unwrap();
        response.value as u32
    }

    pub(crate) fn write_csr(&self, addr: usize, data: u32) {
        let msg = CsrAccessRpcMessage {
            is_write: true,
            addr,
            value: data,
        };
        let send_buf = serde_json::to_vec(&msg).unwrap();
        let emulator_socket = self.emulator_socket.lock().unwrap();
        emulator_socket.send_to(&send_buf, self.emulator_address);
    }
}
